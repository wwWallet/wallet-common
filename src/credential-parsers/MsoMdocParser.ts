import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient, CredentialIssuerInfo } from "../interfaces";
import { DataItem, DeviceSignedDocument, parse } from "@auth0/mdl";
import { fromBase64Url } from "../utils/util";
import { CredentialClaimPath, CredentialFriendlyNameCallback, ImageDataUriCallback, ParsedCredential, VerifiableCredentialFormat } from "../types";
import { cborDecode, cborEncode } from "@auth0/mdl/lib/cbor";
import { IssuerSigned } from "@auth0/mdl/lib/mdoc/model/types";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";

export function MsoMdocParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {


	function extractValidityInfo(issuerSigned: IssuerSigned): { validUntil?: Date, validFrom?: Date, signed?: Date } {
		return issuerSigned.issuerAuth.decodedPayload.validityInfo;
	}

	async function deviceResponseParser(rawCredential: string): Promise<ParsedCredential | null> {
		try {
			const decodedCred = fromBase64Url(rawCredential)
			const parsedMDOC = parse(decodedCred);
			const [parsedDocument] = parsedMDOC.documents as DeviceSignedDocument[];
			const namespace = parsedDocument.issuerSignedNameSpaces[0];

			const attrValues = parsedDocument.getIssuerNameSpace(namespace);
			const renderer = OpenID4VCICredentialRendering({ httpClient: args.httpClient });

			let credentialFriendlyName: CredentialFriendlyNameCallback = async () => null;
			let dataUri: ImageDataUriCallback = async () => null;

			const mdocDisplayConfig = {
				name: "mdoc Verifiable Credential"
			}

			credentialFriendlyName = async (
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {

				return 'mdoc Verifiable Credential';
			};

			dataUri = async (
				filter
			): Promise<string | null> => {
				return await renderer.renderCustomSvgTemplate({ signedClaims: attrValues, displayConfig: mdocDisplayConfig })
					.then((res) => res)
					.catch((err) => { console.error(err); return null; });
			}

			return {
				metadata: {
					credential: {
						format: VerifiableCredentialFormat.MSO_MDOC,
						doctype: parsedDocument.docType,
						image: {
							dataUri: dataUri,
						},
						name: credentialFriendlyName,
					},
					issuer: {
						id: parsedDocument.issuerSigned.issuerAuth.certificate.issuer,
						name: parsedDocument.issuerSigned.issuerAuth.certificate.issuer
					}
				},
				signedClaims: {
					...attrValues
				},
				validityInfo: {
					...extractValidityInfo(parsedDocument.issuerSigned),
				}
			}
		}
		catch (err) {
			return null;
		}
	}

	async function issuerSignedParser(rawCredential: string, credentialIssuer?: CredentialIssuerInfo | null): Promise<ParsedCredential | null> {
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
			const [parsedDocument] = mdoc.documents;

			const namespace = parsedDocument.issuerSignedNameSpaces[0];
			const attrValues = parsedDocument.getIssuerNameSpace(namespace);

			const allAttrValues = parsedDocument.issuerSignedNameSpaces.reduce<Record<string, unknown>>(
				(acc, ns) => {
					acc[ns] = parsedDocument.getIssuerNameSpace(ns);
					return acc;
				},
				{},
			);

			const renderer = OpenID4VCICredentialRendering({ httpClient: args.httpClient });

			let metadataDocuments: Array<{ claims: any[] }> = [];
			try {
				if (credentialIssuer?.credentialIssuerIdentifier) {
					const { metadata: issuerMetadata } = await getIssuerMetadata(
						args.httpClient,
						credentialIssuer.credentialIssuerIdentifier,
						[]
					);

					const issuerClaimsArray = credentialIssuer?.credentialConfigurationId
						? issuerMetadata?.credential_configurations_supported?.[credentialIssuer.credentialConfigurationId]?.claims
						: undefined;

					const convertedClaims = issuerClaimsArray
						? convertOpenid4vciToSdjwtvcClaims(issuerClaimsArray)
						: undefined;

					if (convertedClaims?.length) {
						metadataDocuments = [{ claims: convertedClaims }];
					}
				}
			} catch (e) {
				console.warn('Issuer metadata unavailable or invalid:', e);
			}

			let credentialFriendlyName: CredentialFriendlyNameCallback = async () => null;
			let dataUri: ImageDataUriCallback = async () => null;

			const mdocDisplayConfig = {
				name: "mdoc Verifiable Credential"
			}

			credentialFriendlyName = async (
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {

				return 'mdoc Verifiable Credential';
			};

			dataUri = async (
				filter?: Array<CredentialClaimPath>,
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {
				return await renderer.renderCustomSvgTemplate({ signedClaims: attrValues, displayConfig: mdocDisplayConfig })
					.then((res) => res)
					.catch((err) => { console.error(err); return null; })
			}

			return {
				metadata: {
					credential: {
						format: VerifiableCredentialFormat.MSO_MDOC,
						doctype: docType as string | undefined ?? "",
						metadataDocuments,
						image: {
							dataUri: dataUri,
						},
						name: credentialFriendlyName,
					},
					issuer: {
						id: parsedDocument.issuerSigned.issuerAuth.certificate.issuer,
						name: parsedDocument.issuerSigned.issuerAuth.certificate.issuer
					}
				},
				signedClaims: {
					...allAttrValues
				},
				validityInfo: {
					...extractValidityInfo(parsedDocument.issuerSigned),
				}
			}

		}
		catch (err) {
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

			const deviceResponseParsingResult = await deviceResponseParser(rawCredential);
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
