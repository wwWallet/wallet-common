import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { CredentialClaimPath, CredentialFriendlyNameCallback, ImageDataUriCallback, MetadataWarning, VerifiableCredentialFormat } from "../types";
import { z } from 'zod';
import { IssuedJpt, parseJpt } from "../jpt";
import { fromBase64Url } from "../utils/util";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { CredentialRenderingService } from "../rendering";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { matchDisplayByLang, matchDisplayByLocale } from "../utils/matchLocalizedDisplay";

export function JptDcParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
	function extractValidityInfo(parsedJpt: IssuedJpt): { validUntil?: Date, validFrom?: Date, signed?: Date } {
		let obj = {};

		const { exp, iat, nbf } = parsedJpt.claims.simple;
		if (exp && typeof exp === 'number') {
			obj = {
				...obj,
				validUntil: new Date(exp * 1000),
			}
		}

		if (iat && typeof iat === 'number') {
			obj = {
				...obj,
				signed: new Date(iat * 1000),
			}
		}

		if (nbf && typeof nbf === 'number') {
			obj = {
				...obj,
				validFrom: new Date(nbf * 1000),
			}
		}
		return obj;
	}

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

			let credentialFriendlyName: CredentialFriendlyNameCallback = async () => null;
			let dataUri: ImageDataUriCallback = async () => null;

			const warnings: MetadataWarning[] = [];

			const { parsedJpt, err } = await (async () => {
				try {
					const parsedJpt = parseJpt(rawCredential);
					return { parsedJpt, err: null };
				}
				catch (err) {
					return { parsedJpt: null, err };
				}
			})();

			if (err || !parsedJpt) {
				return {
					success: false,
					error: CredentialParsingError.CouldNotParse,
				};
			}

			const { issuerHeader: header, claims } = parsedJpt;
			if (!header.vctm || !header?.vctm[0]) {
				return {
					success: false,
					error: CredentialParsingError.VctmMissing,
				};
			}

			const schema = z.enum([VerifiableCredentialFormat.DC_JPT]);
			const typParseResult = await schema.safeParseAsync(header.typ);
			if (typParseResult.error) {
				return {
					success: false,
					error: CredentialParsingError.NotSupportedCredentialType,
				}
			}

			if (!header.iss) {
				return {
					success: false,
					error: CredentialParsingError.FailFetchIssuerMetadata,
				}
			}

			const vctm = JSON.parse(new TextDecoder().decode(fromBase64Url(header.vctm[0])));
			if (!vctm?.claims) {
				return {
					success: false,
					error: CredentialParsingError.VctmDecodeFail,
				};
			}

			const credentialMetadata = vctm;
			if (credentialMetadata) {
				const { metadata: issuerMetadata } = await getIssuerMetadata(args.httpClient, header.iss, warnings);
				const validatedParsedClaims = claims;

				credentialFriendlyName = async (
					preferredLangs: string[] = ['en-US']
				): Promise<string | null> => {
					const vct = credentialMetadata.vct;
					const credentialDisplayArray = credentialMetadata.display;
					const issuerDisplayArray = vct
						? issuerMetadata?.credential_configurations_supported?.[vct]?.display
						: undefined;

					const credentialDisplayLocalized = matchDisplayByLang(credentialDisplayArray, preferredLangs);
					//@ts-ignore
					if (credentialDisplayLocalized?.name) return credentialDisplayLocalized.name;

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
					const issuerDisplayArray = issuerMetadata?.credential_configurations_supported?.[credentialMetadata.vct]?.display;
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
			}




			return {
				success: true,
				value: {
					issuerHeader: parsedJpt.issuerHeader,
					presentationHeader: "presentationHeader" in parsedJpt ? parsedJpt.presentationHeader : null,
					signedJptClaims: claims,
					metadata: {
						credential: {
							format: typParseResult.data,
							vct: header?.vct as string | undefined ?? "",
							// @ts-ignore
							metadataDocuments: [credentialMetadata],
							image: {
								dataUri: dataUri,
							},
							name: credentialFriendlyName,
						},
						issuer: {
							id: header.iss,
							name: header.iss,
						}
					},
					validityInfo: {
						...extractValidityInfo(parsedJpt)
					},
					warnings,
				}
			}
		},
	}
}
