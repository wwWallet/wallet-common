import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { CredentialClaimPath, ImageDataUriCallback, MetadataWarning, VerifiableCredentialFormat } from "../types";
import { z } from 'zod';
import { IssuedJpt, parseJpt } from "../jpt";
import { fromBase64Url } from "../utils/util";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { CredentialRenderingService } from "../rendering";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";

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

			let dataUri: ImageDataUriCallback | null = null;
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

			let credentialFriendlyName: string | null = null;

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
						dataUri = async (filter?: Array<CredentialClaimPath>) => {
							return await cr
								.renderSvgTemplate({
									json: claims.simple,
									credentialImageSvgTemplate: svgdata,
									sdJwtVcMetadataClaims: credentialMetadata.claims,
									filter: filter,
								})
								.catch(() => null);
						}
					}
				}

				// 2. Fallback: render from simple config
				if (!dataUri && simpleDisplayConfig) {
					dataUri = async (filter?: Array<CredentialClaimPath>) => {
						return await renderer
							.renderCustomSvgTemplate({
								signedClaims: claims.simple,
								displayConfig: { ...credentialDisplayLocalized, ...simpleDisplayConfig },
							})
							.catch(() => null);
					}
				}

				// 3. Fallback: render from issuer metadata display
				if (!dataUri && issuerDisplayLocalized) {
					dataUri = async (filter?: Array<CredentialClaimPath>) => {
						return await renderer
							.renderCustomSvgTemplate({
								signedClaims: claims.simple,
								displayConfig: { ...credentialDisplayLocalized, ...simpleDisplayConfig },
							})
							.catch(() => null);
					}
				}
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
								dataUri: dataUri ?? (async () => null),
							},
							name: credentialFriendlyName ?? "Credential",
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
