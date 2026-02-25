import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { MetadataWarning, VerifiableCredentialFormat } from "../types";
import { SdJwtVcPayloadSchema } from "../schemas";
import { CredentialRenderingService } from "../rendering";
import { getSdJwtVcMetadata } from "../utils/getSdJwtVcMetadata";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { z } from 'zod';
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { TypeMetadata as TypeMetadataSchema } from "../schemas/SdJwtVcTypeMetadataSchema";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";
import { fromBase64, fromBase64Url } from "../utils";

export function SDJWTVCParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
	const encoder = new TextEncoder();

	function canParseSdJwtVc(raw: unknown): raw is string {
		const decoder = new TextDecoder();

		if (typeof raw !== "string") return false;

		if (raw.includes(".")) {
			const { typ } = JSON.parse(decoder.decode(fromBase64Url(raw.split('.')[0])));

			if (typ === VerifiableCredentialFormat.VC_SDJWT) return true;
			if (typ === VerifiableCredentialFormat.DC_SDJWT) return true;

		}
		return false;
	}

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
	const renderer = CustomCredentialSvg({ httpClient: args.httpClient });


	return {
		async parse({ rawCredential, credentialIssuer }) {

			if (!canParseSdJwtVc(rawCredential)) {
				return {
					success: false,
					error: CredentialParsingError.UnsupportedFormat,
				};
			}

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


			const { metadata: issuerMetadata } = validatedParsedClaims.iss ? await getIssuerMetadata(args.httpClient, validatedParsedClaims.iss, warnings) : { metadata: undefined };

			const vctIntegrity = validatedParsedClaims['vct#integrity'] as string | undefined;
			const getSdJwtMetadataResult = await getSdJwtVcMetadata(args.context.vctResolutionEngine, args.context.subtle, args.httpClient, validatedParsedClaims.vct, vctIntegrity, warnings);
			if ('error' in getSdJwtMetadataResult) {
				return {
					success: false,
					error: getSdJwtMetadataResult.error,
				}
			}

			let TypeMetadata: Partial<TypeMetadataSchema> = {};
			let credentialMetadata: TypeMetadataSchema | undefined = undefined;

			const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer?.credentialConfigurationId]
				: undefined;

			if (getSdJwtMetadataResult.credentialMetadata) {

				credentialMetadata = getSdJwtMetadataResult.credentialMetadata

				if (credentialMetadata?.claims) {
					TypeMetadata = { claims: credentialMetadata.claims };
				}
			} else if ('vctm' in parsedHeaders && Array.isArray(parsedHeaders?.vctm)) {
				const sdjwtvcMetadataDocument = parsedHeaders.vctm.map((encodedMetadataDocument: string) =>
					JSON.parse(new TextDecoder().decode(fromBase64(encodedMetadataDocument)))
				).filter(((metadataDocument) => metadataDocument.vct === validatedParsedClaims.vct))[0];
				if (sdjwtvcMetadataDocument) {
					credentialMetadata = sdjwtvcMetadataDocument;
				}
			}

			const friendlyName = friendlyNameResolver({
				credentialDisplayArray: credentialMetadata?.display,
				issuerDisplayArray: credentialIssuerMetadata?.credential_metadata?.display,
				fallbackName: "SD-JWT Verifiable Credential",
			});

			const dataUri = dataUriResolver({
				httpClient: args.httpClient,
				customRenderer: renderer,
				signedClaims: validatedParsedClaims,

				credentialDisplayArray: credentialMetadata?.display,
				issuerDisplayArray: credentialIssuerMetadata?.credential_metadata?.display,

				sdJwtVcRenderer: cr,
				sdJwtVcMetadataClaims: credentialMetadata?.claims,
				fallbackName: "SD-JWT Verifiable Credential",
			});

			if (!TypeMetadata?.claims && credentialIssuerMetadata?.credential_metadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.credential_metadata.claims);
				if (convertedClaims?.length) {
					TypeMetadata = { claims: convertedClaims };
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
							name: friendlyName,
						},
						issuer: {
							id: validatedParsedClaims.iss ?? "UnknownIssuer",
							name: validatedParsedClaims.iss ?? "UnknownIssuer",
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
