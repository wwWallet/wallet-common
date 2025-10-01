import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { CredentialClaimPath, CredentialFriendlyNameCallback, ImageDataUriCallback, MetadataWarning, TypeMetadata, VerifiableCredentialFormat } from "../types";
import { z } from 'zod';
import { IssuedJpt, parseJpt, PresentedJpt } from "../jpt";
import { fromBase64Url } from "../utils/util";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { CredentialRenderingService } from "../rendering";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { matchDisplayByLang, matchDisplayByLocale } from "../utils/matchLocalizedDisplay";
import { TypeMetadata as TypeMetadataSchema } from "../schemas/SdJwtVcTypeMetadataSchema";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";


export function JptDcParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
	function extractValidityInfo(parsedJpt: IssuedJpt | PresentedJpt): { validUntil?: Date, validFrom?: Date, signed?: Date } {
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

			const { issuerHeader } = parsedJpt;
			if (!issuerHeader.vctm || !issuerHeader?.vctm[0]) {
				return {
					success: false,
					error: CredentialParsingError.VctmMissing,
				};
			}

			const schema = z.enum([VerifiableCredentialFormat.DC_JPT]);
			const typParseResult = await schema.safeParseAsync(issuerHeader.typ);
			if (typParseResult.error) {
				return {
					success: false,
					error: CredentialParsingError.NotSupportedCredentialType,
				}
			}

			if (!issuerHeader.iss) {
				return {
					success: false,
					error: CredentialParsingError.FailFetchIssuerMetadata,
				}
			}

			const { metadata: issuerMetadata } = await getIssuerMetadata(args.httpClient, issuerHeader.iss, warnings);

			const vctm: TypeMetadataSchema = JSON.parse(new TextDecoder().decode(fromBase64Url(issuerHeader.vctm[0])));
			const claimsMetadata = vctm?.claims;
			if (!claimsMetadata) {
				return {
					success: false,
					error: CredentialParsingError.VctmDecodeFail,
				};
			}

			const validatedParsedClaims = {
				...parsedJpt.claims.simple,
				iss: issuerHeader.iss, // TODO: Ugly hacky claim injection
				vct: issuerHeader.vct, // TODO: Ugly hacky claim injection
				"vct#integrity": issuerHeader["vct#integrity"], // TODO: Ugly hacky claim injection
			};

			let TypeMetadata: TypeMetadata = {};
			let credentialMetadata: TypeMetadataSchema = {}

			const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer?.credentialConfigurationId]
				: undefined;

			if (vctm) {
				credentialMetadata = vctm;

				if (credentialMetadata?.claims) {
					TypeMetadata = { claims: credentialMetadata.claims };
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

				return 'JPT Verifiable Credential';
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
					displayConfig: { name: "JPT Verifiable Credential" },
				}).catch(() => null);
				if (rendered) return rendered;

				// All attempts failed
				return null;
			};

			if (!TypeMetadata?.claims && credentialIssuerMetadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.claims);
				if (convertedClaims?.length) {
					TypeMetadata = { claims: credentialMetadata.claims };
				}
			}

			return {
				success: true,
				value: {
					issuerHeader: parsedJpt.issuerHeader,
					presentationHeader: "presentationHeader" in parsedJpt ? parsedJpt.presentationHeader : null,
					signedJptClaims: parsedJpt.claims,
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
						...extractValidityInfo(parsedJpt)
					},
					warnings,
				}
			}
		},
	}
}
