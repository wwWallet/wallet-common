import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { CredentialClaimPath, CredentialFriendlyNameCallback, ImageDataUriCallback, MetadataWarning, VerifiableCredentialFormat, TypeMetadata } from "../types";
import { SdJwtVcPayloadSchema } from "../schemas";
import { CredentialRenderingService } from "../rendering";
import { getSdJwtVcMetadata } from "../utils/getSdJwtVcMetadata";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { z } from 'zod';
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { matchDisplayByLang, matchDisplayByLocale } from '../utils/matchLocalizedDisplay';
import { TypeMetadata as TypeMetadataSchema } from "../schemas/SdJwtVcTypeMetadataSchema";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { buildPresenceIndex, pathIsPresent } from "../utils/payloadPresenceIndex";
import { ClaimsWithRequired } from "../utils/ClaimsWithRequired";

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
		async parse({ rawCredential, credentialIssuer }) {
			if (typeof rawCredential !== 'string') {
				return {
					success: false,
					error: CredentialParsingError.InvalidDatatype
				};
			}

			let credentialFriendlyName: CredentialFriendlyNameCallback = async () => null;
			let dataUri: ImageDataUriCallback = async () => null;

			const warnings: MetadataWarning[] = [];

			const { parsedClaims, parsedHeaders, parsedPayload, err } = await (async () => {
				try {
					const parsedSdJwt = await SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher);
					const claims = await parsedSdJwt.getClaims(hasherAndAlgorithm.hasher);
					const headers = await parsedSdJwt.jwt?.header;
					const payload = await parsedSdJwt.jwt?.payload;

					return { parsedClaims: claims as Record<string, unknown>, parsedHeaders: headers, parsedPayload: payload, err: null };
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

			const getSdJwtMetadataResult = await getSdJwtVcMetadata(args.context, args.httpClient, rawCredential, validatedParsedClaims, warnings);
			if ('error' in getSdJwtMetadataResult) {
				return {
					success: false,
					error: getSdJwtMetadataResult.error,
				}
			}

			console.log('parsedPayload',parsedPayload)

			const presenceIndex = buildPresenceIndex(parsedPayload, ["_sd"]);
			const isPresent = (path: Array<string | number | null>) =>
				pathIsPresent(presenceIndex, path);

			let TypeMetadata: TypeMetadata = {};
			let credentialMetadata: TypeMetadataSchema = {}

			const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer?.credentialConfigurationId]
				: undefined;

			if (getSdJwtMetadataResult.credentialMetadata) {

				credentialMetadata = getSdJwtMetadataResult.credentialMetadata

				if (credentialMetadata?.claims) {
					TypeMetadata = { claims: ClaimsWithRequired(credentialMetadata.claims, isPresent) };
				}
			}

			credentialFriendlyName = async (
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {

				// 1. Try to match localized credential display
				const credentialDisplayArray = credentialMetadata.display;
				const credentialDisplayLocalized = matchDisplayByLang(credentialDisplayArray, preferredLangs);
				if (credentialDisplayLocalized?.name) return credentialDisplayLocalized.name;

				// 2. Try to match localized issuer display
				const issuerDisplayArray = credentialIssuerMetadata?.display;
				const issuerDisplayLocalized = matchDisplayByLocale(issuerDisplayArray, preferredLangs);
				if (issuerDisplayLocalized?.name) return issuerDisplayLocalized.name;

				return 'SD-JWT Verifiable Credential';
			};

			dataUri = async (
				filter?: Array<CredentialClaimPath>,
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {

				// 1. Try to match localized credential display
				const credentialDisplayArray = credentialMetadata?.display;
				const credentialDisplayLocalized = matchDisplayByLang(credentialDisplayArray, preferredLangs);

				// 2. Try to match localized issuer display
				const issuerDisplayArray = credentialIssuerMetadata?.display;
				const issuerDisplayLocalized = matchDisplayByLocale(issuerDisplayArray, preferredLangs);

				//@ts-ignore
				const svgTemplateUri = credentialDisplayLocalized?.rendering?.svg_templates?.[0]?.uri || null;
				//@ts-ignore
				const simpleDisplayConfig = credentialDisplayLocalized?.rendering?.simple || null;

				// 1. Try SVG template rendering
				if (svgTemplateUri) {
					const svgResponse = await args.httpClient.get(svgTemplateUri, {}, { useCache: true }).catch(() => null);
					if (svgResponse && svgResponse.status === 200) {
						const svgdata = svgResponse.data as string;
						const rendered = await cr.renderSvgTemplate({
							json: validatedParsedClaims,
							credentialImageSvgTemplate: svgdata,
							sdJwtVcMetadataClaims: credentialMetadata.claims,
							filter,
						}).catch(() => null);
						if (rendered) return rendered;
					}
				}

				// 2. Fallback: simple rendering from credential display
				if (simpleDisplayConfig && credentialDisplayLocalized) {
					const rendered = await renderer.renderCustomSvgTemplate({
						signedClaims: validatedParsedClaims,
						displayConfig: { ...credentialDisplayLocalized, ...simpleDisplayConfig },
					}).catch(() => null);
					if (rendered) return rendered;
				}

				// 3. Fallback: rendering from issuer metadata display
				if (issuerDisplayLocalized) {
					const rendered = await renderer.renderCustomSvgTemplate({
						signedClaims: validatedParsedClaims,
						displayConfig: issuerDisplayLocalized,
					}).catch(() => null);
					if (rendered) return rendered;
				}

				const rendered = await renderer.renderCustomSvgTemplate({
					signedClaims: validatedParsedClaims,
					displayConfig: { name: "SD-JWT Verifiable Credential" },
				}).catch(() => null);
				if (rendered) return rendered;

				// All attempts failed
				return null;
			};

			if (!TypeMetadata?.claims && credentialIssuerMetadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.claims);
				if (convertedClaims?.length) {
					TypeMetadata = { claims: ClaimsWithRequired(credentialMetadata.claims, isPresent) };
				}
			}

			return {
				success: true,
				value: {
					signedClaims: validatedParsedClaims,
					metadata: {
						credential: {
							format: typParseResult.data,
							vct: validatedParsedClaims?.vct as string | undefined ?? "",
							TypeMetadata,
							image: {
								dataUri: dataUri,
							},
							name: credentialFriendlyName,
						},
						issuer: {
							id: validatedParsedClaims.iss,
							name: validatedParsedClaims.iss,
						}
					},
					validityInfo: {
						...extractValidityInfo(validatedParsedClaims)
					},
					warnings: getSdJwtMetadataResult.warnings
				}
			}
		},
	}
}
