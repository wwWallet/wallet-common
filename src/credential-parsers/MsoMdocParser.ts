import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient, CredentialIssuerInfo } from "../interfaces";
import { cborDecode, DeviceResponse, IssuerSigned } from "@owf/mdoc";
import { X509Certificate } from "@peculiar/x509";
import { fromBase64Url } from "../utils/util";
import { FriendlyNameCallback, ImageDataUriCallback, ParsedCredential, VerifiableCredentialFormat, TypeMetadataResult } from "../types";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import type { z } from "zod";
import { OpenidCredentialIssuerMetadataSchema, } from "../schemas";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";

type IssuerMetadata = z.infer<typeof OpenidCredentialIssuerMetadataSchema>;

export function MsoMdocParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {

	function looksLikeCborMap(raw: unknown): raw is string {
		if (typeof raw !== "string") return false;

		let bytes: Uint8Array;
		try {
			bytes = fromBase64Url(raw);
		} catch {
			return false;
		}
		if (bytes.length === 0) return false;

		const first = bytes[0];

		// CBOR major type 5 = map.
		// Definite maps: 0xA0..0xBB
		// Indefinite map: 0xBF
		// 0xBC..0xBE are reserved/invalid.
		return (first >= 0xA0 && first <= 0xBB) || first === 0xBF;
	}

	function extractValidityInfo(issuerSigned: IssuerSigned): { validUntil?: Date, validFrom?: Date, signed?: Date } {
		const validityInfo = issuerSigned.issuerAuth.mobileSecurityObject.validityInfo;
		return {
			signed: validityInfo.signed,
			validFrom: validityInfo.validFrom,
			validUntil: validityInfo.validUntil,
		};
	}

	function collectAllAttrValues(issuerSigned: IssuerSigned): Record<string, unknown> {
		const issuerNamespaces = issuerSigned.issuerNamespaces?.issuerNamespaces ?? new Map();
		return Array.from(issuerNamespaces.entries()).reduce<Record<string, unknown>>((acc, [ns, items]) => {
			acc[ns] = items.reduce<Record<string, unknown>>((nsAcc, item) => {
				nsAcc[item.elementIdentifier] = item.elementValue;
				return nsAcc;
			}, {});
			return acc;
		}, {});
	}

	function extractIssuerName(issuerSigned: IssuerSigned): string {
		try {
			const certificateBytes = new Uint8Array(issuerSigned.issuerAuth.certificate);
			return new X509Certificate(certificateBytes).issuerName.toString();
		} catch {
			return "Unknown issuer";
		}
	}

	async function fetchIssuerMetadataAndDocs(
		credentialIssuer?: CredentialIssuerInfo | null
	): Promise<{ issuerMetadata: IssuerMetadata | null; TypeMetadata: TypeMetadataResult }> {
		let issuerMetadata: IssuerMetadata | null = null;
		let TypeMetadata: TypeMetadataResult = {};

		try {
			if (credentialIssuer?.credentialIssuerIdentifier) {
				const { metadata } = await getIssuerMetadata(args.httpClient, credentialIssuer.credentialIssuerIdentifier, []);
				issuerMetadata = metadata ?? null;

				const issuerClaimsArray = credentialIssuer?.credentialConfigurationId
					? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.credential_metadata?.claims
					: undefined;

				const convertedClaims = issuerClaimsArray ? convertOpenid4vciToSdjwtvcClaims(issuerClaimsArray) : undefined;
				if (convertedClaims?.length) {
					TypeMetadata = { claims: convertedClaims };
				}
			}
		} catch (e) {
			console.warn("Issuer metadata unavailable or invalid:", e);
		}

		return { issuerMetadata, TypeMetadata };
	}

	function toParsedCredential(
		docType: string,
		issuerSigned: IssuerSigned,
		signedClaims: Record<string, unknown>,
		TypeMetadata: TypeMetadataResult,
		friendlyName: FriendlyNameCallback,
		dataUri: ImageDataUriCallback
	): ParsedCredential {
		const issuerName = extractIssuerName(issuerSigned);

		return {
			metadata: {
				credential: {
					format: VerifiableCredentialFormat.MSO_MDOC,
					doctype: docType,
					TypeMetadata,
					image: { dataUri },
					name: friendlyName
				},
				issuer: {
					id: issuerName,
					name: issuerName
				}
			},
			signedClaims: { ...signedClaims },
			validityInfo: { ...extractValidityInfo(issuerSigned) }
		};
	}

	async function deviceResponseParser(
		rawCredential: string,
		credentialIssuer?: CredentialIssuerInfo | null
	): Promise<ParsedCredential | null> {
		try {
			const decodedCred = fromBase64Url(rawCredential);
			const parsedMDOC = DeviceResponse.decode(decodedCred);
			const [parsedDocument] = parsedMDOC.documents ?? [];
			if (!parsedDocument) return null;

			const signedClaims = collectAllAttrValues(parsedDocument.issuerSigned);
			const renderer = CustomCredentialSvg({ httpClient: args.httpClient });
			const { issuerMetadata, TypeMetadata } = await fetchIssuerMetadataAndDocs(credentialIssuer);

			const issuerDisplayArray = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.credential_metadata?.display
				: undefined;

			const friendlyName = friendlyNameResolver({
				issuerDisplayArray,
				fallbackName: "mdoc Verifiable Credential",
			});

			const dataUri = dataUriResolver({
				httpClient: args.httpClient,
				customRenderer: renderer,
				issuerDisplayArray,
				fallbackName: "mdoc Verifiable Credential",
			});

			return toParsedCredential(parsedDocument.docType, parsedDocument.issuerSigned, signedClaims, TypeMetadata, friendlyName, dataUri);
		} catch {
			return null;
		}
	}

	async function issuerSignedParser(
		rawCredential: string,
		credentialIssuer?: CredentialIssuerInfo | null
	): Promise<ParsedCredential | null> {
		try {
			const credentialBytes = fromBase64Url(rawCredential);
			const issuerSigned = IssuerSigned.decode(credentialBytes);
			const docType = issuerSigned.issuerAuth.mobileSecurityObject.docType;

			const signedClaims = collectAllAttrValues(issuerSigned);
			const renderer = CustomCredentialSvg({ httpClient: args.httpClient });
			const { issuerMetadata, TypeMetadata } = await fetchIssuerMetadataAndDocs(credentialIssuer);

			const issuerDisplayArray = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.credential_metadata?.display
				: undefined;

			const friendlyName = friendlyNameResolver({
				issuerDisplayArray,
				fallbackName: "mdoc Verifiable Credential",
			});

			const dataUri = dataUriResolver({
				httpClient: args.httpClient,
				customRenderer: renderer,
				issuerDisplayArray,
				fallbackName: "mdoc Verifiable Credential",
			});

			return toParsedCredential(docType, issuerSigned, signedClaims, TypeMetadata, friendlyName, dataUri);
		} catch {
			return null;
		}
	}

	return {
		async parse({ rawCredential, credentialIssuer }) {
			if (!looksLikeCborMap(rawCredential)) {
				return {
					success: false,
					error: CredentialParsingError.UnsupportedFormat,
				};
			}

			const deviceResponseParsingResult = await deviceResponseParser(rawCredential, credentialIssuer ?? null);
			if (deviceResponseParsingResult) {
				return {
					success: true,
					value: deviceResponseParsingResult
				}
			}

			const issuerSignedParsingResult = await issuerSignedParser(rawCredential, credentialIssuer ?? null);
			if (issuerSignedParsingResult) {
				return {
					success: true,
					value: issuerSignedParsingResult,
				}
			}

			return {
				success: false,
				error: CredentialParsingError.CouldNotParse,
			}
		},
	}
}
