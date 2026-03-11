import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient, CredentialIssuerInfo } from "../interfaces";
import { MetadataWarning, TypeMetadataResult, VerifiableCredentialFormat } from "../types";
import { JwtVcJsonHeaderSchema, JwtVcJsonPayloadSchema } from "../schemas/JwtVcJsonPayloadSchema";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";
import { fromBase64Url } from "../utils";

export function JWTVCJSONParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
	const decoder = new TextDecoder();

	function canParseJwtVcJson(raw: unknown): raw is string {
		if (typeof raw !== "string") return false;

		const parts = raw.split(".");
		if (parts.length !== 3) return false;

		// Exclude SD-JWT (contains ~) — the SDJWTVCParser handles those
		if (raw.includes("~")) return false;

		try {
			const header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
			// Reject if typ indicates SD-JWT
			if (
				header.typ === VerifiableCredentialFormat.VC_SDJWT ||
				header.typ === VerifiableCredentialFormat.DC_SDJWT
			) {
				return false;
			}
			return true;
		} catch {
			return false;
		}
	}

	function extractValidityInfo(payload: { exp?: number, iat?: number, nbf?: number }): {
		validUntil?: Date, validFrom?: Date, signed?: Date
	} {
		const obj: { validUntil?: Date; validFrom?: Date; signed?: Date } = {};
		if (payload.exp) {
			obj.validUntil = new Date(payload.exp * 1000);
		}
		if (payload.iat) {
			obj.signed = new Date(payload.iat * 1000);
		}
		if (payload.nbf) {
			obj.validFrom = new Date(payload.nbf * 1000);
		}
		return obj;
	}

	return {
		async parse({ rawCredential, credentialIssuer }) {

			if (!canParseJwtVcJson(rawCredential)) {
				return {
					success: false,
					error: CredentialParsingError.UnsupportedFormat,
				};
			}

			const warnings: MetadataWarning[] = [];

			const parts = rawCredential.split(".");
			let header, payload;
			try {
				header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
				payload = JSON.parse(decoder.decode(fromBase64Url(parts[1])));
			} catch {
				return {
					success: false,
					error: CredentialParsingError.CouldNotParse,
				};
			}

			// Validate header
			const headerResult = JwtVcJsonHeaderSchema.safeParse(header);
			if (!headerResult.success) {
				return {
					success: false,
					error: CredentialParsingError.CouldNotParse,
				};
			}

			// Validate payload
			const payloadResult = JwtVcJsonPayloadSchema.safeParse(payload);
			if (!payloadResult.success) {
				return {
					success: false,
					error: CredentialParsingError.InvalidSdJwtVcPayload,
				};
			}

			const validatedPayload = payloadResult.data;

			// Extract credential type from vc.type or top-level type
			const vcTypes: string[] = validatedPayload.vc?.type ?? [];

			// Fetch issuer metadata if available
			const { metadata: issuerMetadata } = validatedPayload.iss
				? await getIssuerMetadata(args.httpClient, validatedPayload.iss, warnings)
				: { metadata: undefined };

			const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]
				: undefined;

			let TypeMetadata: TypeMetadataResult = {};
			if (credentialIssuerMetadata?.credential_metadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.credential_metadata.claims);
				if (convertedClaims?.length) {
					TypeMetadata = { claims: convertedClaims };
				}
			}

			const issuerDisplayArray = credentialIssuerMetadata?.credential_metadata?.display;
			const renderer = CustomCredentialSvg({ httpClient: args.httpClient });

			const friendlyName = friendlyNameResolver({
				issuerDisplayArray,
				fallbackName: "JWT Verifiable Credential",
			});

			const dataUri = dataUriResolver({
				httpClient: args.httpClient,
				customRenderer: renderer,
				issuerDisplayArray,
				fallbackName: "JWT Verifiable Credential",
			});

			return {
				success: true,
				value: {
					signedClaims: validatedPayload,
					metadata: {
						credential: {
							format: VerifiableCredentialFormat.JWT_VC_JSON,
							type: vcTypes,
							TypeMetadata,
							image: {
								dataUri: dataUri,
							},
							name: friendlyName,
						},
						issuer: {
							id: validatedPayload.iss ?? "UnknownIssuer",
							name: validatedPayload.iss ?? "UnknownIssuer",
						},
					},
					validityInfo: {
						...extractValidityInfo(validatedPayload),
					},
					warnings: warnings.length > 0 ? warnings : undefined,
				},
			};
		},
	};
}
