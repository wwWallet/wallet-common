import { SDJwt } from "@sd-jwt/core";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { MetadataWarning, VerifiableCredentialFormat } from "../types";
import { SdJwtVcPayloadSchema } from "../schemas";
import { CredentialRenderingService } from "../rendering";
import { fetchAndMergeMetadata } from "../utils/getSdJwtVcMetadata";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { z } from 'zod';
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { CredentialMetadata } from "../types";

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
			const vctFetcher = async function (uri: string, integrity?: string) {
				const { header } = await SDJwt.extractJwt<{ vctm?: string[] }>(rawCredential)
				const result = await fetchAndMergeMetadata(
					args.context,
					args.httpClient,
					uri,
					header?.vctm?.map(vctm => JSON.parse(Buffer.from(vctm, 'base64url').toString('utf-8'))) || [],
					new Set<string>(),
					integrity)
				if (!result || result.error) {
					throw new Error('Could not fetch VCT Metadata')
				}

				return result as { vct: string }
			}
			const sdjwt = new SDJwtVcInstance({
				vctFetcher
			})

			if (typeof rawCredential !== 'string') {
				return {
					success: false,
					error: CredentialParsingError.InvalidDatatype
				};
			}

			let dataUri: string | null = null;
			const warnings: MetadataWarning[] = [];

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

			const schema = z.enum([VerifiableCredentialFormat.VC_SDJWT, VerifiableCredentialFormat.DC_SDJWT]);
			const typParseResult = await schema.safeParseAsync(parsedHeaders.typ);
			if (typParseResult.error) {
				return {
					success: false,
					error: CredentialParsingError.NotSupportedCredentialType,
				}
			}

			// sd-jwt vc Payload Schema Validation
			let validatedParsedClaims;
			try {
				validatedParsedClaims = SdJwtVcPayloadSchema.parse(parsedClaims);
			} catch (err) {
				return {
					success: false,
					error: CredentialParsingError.InvalidSdJwtVcPayload,
				};
			}

			const { metadata: issuerMetadata } = await getIssuerMetadata(args.httpClient, validatedParsedClaims.iss, warnings);

			let credentialFriendlyName: string | null = null;

			let credentialMetadata: CredentialMetadata;
			try {
				credentialMetadata = await sdjwt.getVct(rawCredential);

				// Get localized display metadata from issuer metadata
				const issuerDisplay = issuerMetadata?.credential_configurations_supported?.[credentialMetadata.vct]?.display;
				let issuerDisplayLocalized = null;
				if (Array.isArray(issuerDisplay)) {
					const matchedDisplay = issuerDisplay.find((d: any) => d.locale === args.context.lang || d.locale.substring(0, 2) === args.context.lang);
					if (matchedDisplay) {
						issuerDisplayLocalized = matchedDisplay;
					} else {
						// select the first display as a fallback
						issuerDisplayLocalized = issuerDisplay[0];
					}
				}

				// Get localized display metadata from credential
				let credentialDisplayLocalized = null;
				if (Array.isArray(credentialMetadata?.display)) {
					const matchedDisplay = credentialMetadata.display.find((d: any) => d.lang === args.context.lang || d.lang.substring(0, 2) === args.context.lang);
					if (matchedDisplay) {
						credentialDisplayLocalized = matchedDisplay;
					} else {
						// select the first display as a fallback
						credentialDisplayLocalized = credentialMetadata.display[0]
					}
				}

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
								json: validatedParsedClaims,
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
							signedClaims: validatedParsedClaims,
							displayConfig: { ...credentialDisplayLocalized, ...simpleDisplayConfig },
						})
						.catch(() => null);
				}

				// 3. Fallback: render from issuer metadata display
				if (!dataUri && issuerDisplayLocalized) {
					dataUri = await renderer
						.renderCustomSvgTemplate({
							signedClaims: validatedParsedClaims,
							displayConfig: issuerDisplayLocalized,
						})
						.catch(() => null);
				}
			} catch (err) {
				console.error(err)
			}

			return {
				success: true,
				value: {
					signedClaims: validatedParsedClaims,
					metadata: {
						credential: {
							format: typParseResult.data,
							vct: validatedParsedClaims?.vct as string | undefined ?? "",
							// @ts-ignore
							metadataDocuments: [credentialMetadata],
							image: {
								dataUri: dataUri ?? "",
							},
							name: credentialFriendlyName ?? "Credential",
						},
						issuer: {
							id: validatedParsedClaims.iss,
							name: validatedParsedClaims.iss,
						}
					},
					validityInfo: {
						...extractValidityInfo(validatedParsedClaims)
					},
					warnings,
				}
			}
		},
	}
}
