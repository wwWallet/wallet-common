import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { MetadataWarning, VerifiableCredentialFormat } from "../types";
import { SdJwtVcPayloadSchema } from "../schemas";
import { CredentialRenderingService } from "../rendering";
import { getSdJwtVcMetadata } from "../utils/getSdJwtVcMetadata";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { z } from 'zod';
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { TypeMetadata as TypeMetadataSchema } from "../schemas/SdJwtVcTypeMetadataSchema";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";

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

			const getSdJwtMetadataResult = await getSdJwtVcMetadata(args.context, args.httpClient, validatedParsedClaims.vct, warnings);
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
			}

			const friendlyName = friendlyNameResolver({
				credentialDisplayArray: credentialMetadata?.display,
				issuerDisplayArray: credentialIssuerMetadata?.display,
				fallbackName: "SD-JWT Verifiable Credential",
			});

			const dataUri = dataUriResolver({
				httpClient: args.httpClient,
				customRenderer: renderer,
				signedClaims: validatedParsedClaims,

				credentialDisplayArray: credentialMetadata?.display,
				issuerDisplayArray: credentialIssuerMetadata?.display,

				sdJwtVcRenderer: cr,
				sdJwtVcMetadataClaims: credentialMetadata?.claims,
				fallbackName: "SD-JWT Verifiable Credential",
			});

			if (!TypeMetadata?.claims && credentialIssuerMetadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.claims);
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
