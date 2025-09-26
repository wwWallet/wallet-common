import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient, CredentialIssuerInfo } from "../interfaces";
import { DataItem, DeviceSignedDocument, parse } from "@auth0/mdl";
import { fromBase64Url } from "../utils/util";
import { CredentialClaimPath, CredentialFriendlyNameCallback, ImageDataUriCallback, ParsedCredential, VerifiableCredentialFormat, TypeMetadata } from "../types";
import { cborDecode, cborEncode } from "@auth0/mdl/lib/cbor";
import { IssuerSigned } from "@auth0/mdl/lib/mdoc/model/types";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";
import { matchDisplayByLocale } from '../utils/matchLocalizedDisplay';
import type { z } from "zod";
import { OpenidCredentialIssuerMetadataSchema, } from "../schemas";

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
	): Promise<{ issuerMetadata: IssuerMetadata | null; TypeMetadata: TypeMetadata }> {
		let issuerMetadata: IssuerMetadata | null = null;
		let TypeMetadata: TypeMetadata = {};

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

	function makeCredentialFriendlyName(
		issuerMetadata: IssuerMetadata | null,
		credentialIssuer?: CredentialIssuerInfo | null
	): CredentialFriendlyNameCallback {
		return async (preferredLangs: string[] = ["en-US"]): Promise<string | null> => {
			const issuerDisplayArray = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.display
				: undefined;

			const issuerDisplayLocalized = matchDisplayByLocale(issuerDisplayArray, preferredLangs);
			if (issuerDisplayLocalized?.name) return issuerDisplayLocalized.name;

			return "mdoc Verifiable Credential";
		};
	}

	function makeDataUri(
		renderer: ReturnType<typeof OpenID4VCICredentialRendering>,
		signedClaims: Record<string, unknown>,
		issuerMetadata: IssuerMetadata | null,
		credentialIssuer?: CredentialIssuerInfo | null
	): ImageDataUriCallback {
		const mdocDisplayConfig = { name: "mdoc Verifiable Credential" };
		return async (filter?: Array<CredentialClaimPath>, preferredLangs: string[] = ["en-US"]) => {
			try {

				const issuerDisplayArray = credentialIssuer?.credentialConfigurationId
					? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.display
					: undefined;

				const issuerDisplayLocalized = matchDisplayByLocale(issuerDisplayArray, preferredLangs);

				return await renderer.renderCustomSvgTemplate({ signedClaims, displayConfig: issuerDisplayLocalized ?? mdocDisplayConfig });
			} catch (err) {
				console.error(err);
				return null;
			}
		};
	}

	function toParsedCredential(
		parsedDocument: DeviceSignedDocument,
		signedClaims: Record<string, unknown>,
		TypeMetadata: TypeMetadata,
		credentialFriendlyName: CredentialFriendlyNameCallback,
		dataUri: ImageDataUriCallback
	): ParsedCredential {
		return {
			metadata: {
				credential: {
					format: VerifiableCredentialFormat.MSO_MDOC,
					doctype: parsedDocument.docType,
					TypeMetadata,
					image: { dataUri },
					name: credentialFriendlyName
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
			const renderer = OpenID4VCICredentialRendering({ httpClient: args.httpClient });
			const { issuerMetadata, TypeMetadata } = await fetchIssuerMetadataAndDocs(credentialIssuer);

			const credentialFriendlyName = makeCredentialFriendlyName(issuerMetadata, credentialIssuer);
			const dataUri = makeDataUri(renderer, {}, issuerMetadata, credentialIssuer);

			return toParsedCredential(parsedDocument, signedClaims, TypeMetadata, credentialFriendlyName, dataUri);
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
			const renderer = OpenID4VCICredentialRendering({ httpClient: args.httpClient });
			const { issuerMetadata, TypeMetadata } = await fetchIssuerMetadataAndDocs(credentialIssuer);

			const credentialFriendlyName = makeCredentialFriendlyName(issuerMetadata, credentialIssuer);
			const dataUri = makeDataUri(renderer, {}, issuerMetadata, credentialIssuer);

			return toParsedCredential(parsedDocument, signedClaims, TypeMetadata, credentialFriendlyName, dataUri);
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
