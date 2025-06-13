import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { VerifiableCredentialFormat } from "../types";
import { CredentialRenderingService } from "../rendering";
import { getSdJwtVcMetadata } from "../utils/getSdJwtVcMetadata";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { z } from 'zod';

export function SDJWTVCParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
	const encoder = new TextEncoder();

	function extractValidityInfo(jwtPayload: { exp?: number, iat?: number, nbf?: number }): { validUntil?: Date, validFrom?: Date, signed?: Date } {
		let obj = {};
		if (jwtPayload.exp) {
			obj = {
				...obj,
				validUntil: new Date(jwtPayload.exp * 1000),
			}
		}
		if (jwtPayload.iat) {
			obj = {
				...obj,
				signed: new Date(jwtPayload.iat * 1000),
			}
		}

		if (jwtPayload.nbf) {
			obj = {
				...obj,
				validFrom: new Date(jwtPayload.nbf * 1000),
			}
		}
		return obj;
	}

	// Encoding the string into a Uint8Array
	const hasherAndAlgorithm: HasherAndAlg = {
		hasher: (data: string | ArrayBuffer, alg: string) => {
			const encoded =
				typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);

			return args.context.subtle.digest(alg, encoded).then((v) => new Uint8Array(v));
		},
		alg: 'sha-256',
	};

	const cr = CredentialRenderingService();
	const renderer = OpenID4VCICredentialRendering({ httpClient: args.httpClient });


	return {
		async parse({ rawCredential }) {
			if (typeof rawCredential !== 'string') {
				return {
					success: false,
					error: CredentialParsingError.InvalidDatatype
				};
			}

			let dataUri: string | null = null;

			const { parsedClaims, parsedHeaders, err } = await (async () => {
				try {
					const parsedSdJwt = await SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher);
					const claims = await parsedSdJwt.getClaims(hasherAndAlgorithm.hasher);
					const headers = await parsedSdJwt.jwt?.header;
					return { parsedClaims: claims as Record<string, unknown>, parsedHeaders: headers, err: null };
				}
				catch (err) {
					return { parsedClaims: null, parsedHeaders: null, err: err };
				}

			})();
			if (err || !parsedClaims || !parsedHeaders) {
				return {
					success: false,
					error: CredentialParsingError.CouldNotParse,
				};
			}

			if (typeof parsedClaims.iss !== 'string') {
				return {
					success: false,
					error: CredentialParsingError.MissingIssuerIdentifier,
				}
			}

			// Fetch issuer metadata
			const issuerResponse = await args.httpClient
				.get(`${parsedClaims.iss}/.well-known/openid-credential-issuer`, {}, { useCache: true })
				.catch(() => null);

			const issuerMetadata = issuerResponse?.data as {
				credential_configurations_supported?: Record<string, any>;
			} | null;

			let credentialFriendlyName: string | null = null;

			const getSdJwtMetadataResult = await getSdJwtVcMetadata(args.context, args.httpClient, rawCredential, parsedClaims);
			if ('error' in getSdJwtMetadataResult) {
				return {
					success: false,
					error: getSdJwtMetadataResult.error,
					message: getSdJwtMetadataResult.message,
				}
			} else if (getSdJwtMetadataResult.credentialMetadata) {

				const { credentialMetadata } = getSdJwtMetadataResult;

				// Get localized display metadata from issuer metadata
				const issuerDisplay = issuerMetadata?.credential_configurations_supported?.[credentialMetadata.vct]?.display;
				const issuerDisplayLocalized = Array.isArray(issuerMetadata?.credential_configurations_supported?.[credentialMetadata.vct]?.display)
					? issuerDisplay.find((d: any) => d.locale === args.context.lang)
					: null;

				// Get localized display metadata from credential
				const credentialDisplayLocalized = Array.isArray(credentialMetadata?.display)
					? credentialMetadata.display.find((d: any) => d.lang === args.context.lang)
					: null;

				credentialFriendlyName = credentialDisplayLocalized?.name ?? null;

				let credentialImageSvgTemplateURL: string | null = credentialDisplayLocalized?.rendering?.svg_templates?.[0]?.uri || null;
				const simpleDisplayConfig = credentialDisplayLocalized?.rendering?.simple || null;

				// 1. Try to fetch SVG template and render
				if (credentialImageSvgTemplateURL) {
					const svgResponse = await args.httpClient.get(credentialImageSvgTemplateURL, {}, { useCache: true }).then((res) => res).catch(() => null);
					if (svgResponse && svgResponse.status === 200) {
						const svgdata = svgResponse.data as string;
						dataUri = await cr
							.renderSvgTemplate({
								json: parsedClaims,
								credentialImageSvgTemplate: svgdata,
								sdJwtVcMetadataClaims: credentialMetadata.claims,
							})
							.catch(() => null);
					}
				}

				// 2. Fallback: render from simple config
				if (!dataUri && simpleDisplayConfig) {
					dataUri = await renderer
						.renderCustomSvgTemplate({
							signedClaims: parsedClaims,
							displayConfig: { ...credentialDisplayLocalized, ...simpleDisplayConfig },
						})
						.catch(() => null);
				}

				// 3. Fallback: render from issuer metadata display
				if (!dataUri && issuerDisplayLocalized) {
					dataUri = await renderer
						.renderCustomSvgTemplate({
							signedClaims: parsedClaims,
							displayConfig: issuerDisplayLocalized,
						})
						.catch(() => null);
				}
			}

			const schema = z.enum([VerifiableCredentialFormat.VC_SDJWT, VerifiableCredentialFormat.DC_SDJWT]);
			const typParseResult = await schema.safeParseAsync(parsedHeaders.typ);
			if (typParseResult.error) {
				return {
					success: false,
					error: CredentialParsingError.NotSupportedCredentialType,
				}
			}

			return {
				success: true,
				value: {
					signedClaims: parsedClaims,
					metadata: {
						credential: {
							format: typParseResult.data,
							vct: parsedClaims?.vct as string | undefined ?? "",
							// @ts-ignore
							metadataDocuments: [getSdJwtMetadataResult.credentialMetadata],
							image: {
								dataUri: dataUri ?? "",
							},
							name: credentialFriendlyName ?? "Credential",
						},
						issuer: {
							id: parsedClaims.iss,
							name: parsedClaims.iss,
						}
					},
					validityInfo: {
						...extractValidityInfo(parsedClaims)
					},
					warnings:getSdJwtMetadataResult.warnings
				}
			}
		},
	}
}
