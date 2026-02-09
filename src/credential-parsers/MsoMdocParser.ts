import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient, CredentialIssuerInfo } from "../interfaces";
import { DataItem, DeviceSignedDocument, parse } from "@auth0/mdl";
import { fromBase64Url } from "../utils/util";
import { FriendlyNameCallback, ImageDataUriCallback, ParsedCredential, VerifiableCredentialFormat, TypeMetadataResult } from "../types";
import { cborDecode, cborEncode } from "@auth0/mdl/lib/cbor";
import { IssuerSigned } from "@auth0/mdl/lib/mdoc/model/types";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import type { z } from "zod";
import { OpenidCredentialIssuerMetadataSchema, } from "../schemas";
import { dataUriResolver } from "../resolvers/dataUriResolver";
import { friendlyNameResolver } from "../resolvers/friendlyNameResolver";

type IssuerMetadata = z.infer<typeof OpenidCredentialIssuerMetadataSchema>;

export function MsoMdocParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {

	function extractValidityInfo(issuerSigned: IssuerSigned): { validUntil?: Date, validFrom?: Date, signed?: Date } {
		return issuerSigned.issuerAuth.decodedPayload.validityInfo;
	}

	function collectAllAttrValues(parsedDocument: DeviceSignedDocument): Record<string, unknown> {
		return parsedDocument.issuerSignedNameSpaces.reduce<Record<string, unknown>>((acc, ns) => {
			acc[ns] = parsedDocument.getIssuerNameSpace(ns);
			return acc;
		}, {});
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
					? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.claims
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
		parsedDocument: DeviceSignedDocument,
		signedClaims: Record<string, unknown>,
		TypeMetadata: TypeMetadataResult,
		friendlyName: FriendlyNameCallback,
		dataUri: ImageDataUriCallback
	): ParsedCredential {
		return {
			metadata: {
				credential: {
					format: VerifiableCredentialFormat.MSO_MDOC,
					doctype: parsedDocument.docType,
					TypeMetadata,
					image: { dataUri },
					name: friendlyName
				},
				issuer: {
					id: parsedDocument.issuerSigned.issuerAuth.certificate.issuer,
					name: parsedDocument.issuerSigned.issuerAuth.certificate.issuer
				}
			},
			signedClaims: { ...signedClaims },
			validityInfo: { ...extractValidityInfo(parsedDocument.issuerSigned) }
		};
	}

	async function deviceResponseParser(
		rawCredential: string,
		credentialIssuer?: CredentialIssuerInfo | null
	): Promise<ParsedCredential | null> {
		try {
			const decodedCred = fromBase64Url(rawCredential);
			const parsedMDOC = parse(decodedCred);
			const [parsedDocument] = parsedMDOC.documents as DeviceSignedDocument[];

			const signedClaims = collectAllAttrValues(parsedDocument);
			const renderer = CustomCredentialSvg({ httpClient: args.httpClient });
			const { issuerMetadata, TypeMetadata } = await fetchIssuerMetadataAndDocs(credentialIssuer);

			const issuerDisplayArray = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.display
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

			return toParsedCredential(parsedDocument, signedClaims, TypeMetadata, friendlyName, dataUri);
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
			const issuerSigned: Map<string, unknown> = cborDecode(credentialBytes);
			const [header, _, payload, sig] = issuerSigned.get('issuerAuth') as Array<Uint8Array>;
			const decodedIssuerAuthPayload: DataItem = cborDecode(payload);
			const docType = decodedIssuerAuthPayload.data.get('docType');
			const m = {
				version: '1.0',
				documents: [new Map([
					['docType', docType],
					['issuerSigned', issuerSigned]
				])],
				status: 0
			};
			const encoded = cborEncode(m);
			const mdoc = parse(encoded);
			const [parsedDocument] = mdoc.documents as DeviceSignedDocument[];

			const signedClaims = collectAllAttrValues(parsedDocument);
			const renderer = CustomCredentialSvg({ httpClient: args.httpClient });
			const { issuerMetadata, TypeMetadata } = await fetchIssuerMetadataAndDocs(credentialIssuer);

			const issuerDisplayArray = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.display
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

			return toParsedCredential(parsedDocument, signedClaims, TypeMetadata, friendlyName, dataUri);
		} catch {
			return null;
		}
	}

	return {
		async parse({ rawCredential, credentialIssuer }) {

			if (typeof rawCredential != 'string') {
				return {
					success: false,
					error: CredentialParsingError.InvalidDatatype,
				}
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
