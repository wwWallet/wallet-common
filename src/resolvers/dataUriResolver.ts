import type { HttpClient, CredentialRendering, CustomCredentialSvgI } from "../interfaces";
import type { CredentialClaimPath, ImageDataUriCallback } from "../types";
import { rankSvgTemplates } from "../functions/pickBestSvgTemplate";
import { matchDisplayByLocale } from "../utils/matchLocalizedDisplay";
import type { TypeDisplayEntry, ClaimMetadataEntry, SvgTemplateProperties } from "../schemas/SdJwtVcTypeMetadataSchema";
import type { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";
import { loadSvgTemplate } from "./loadSvgTemplate";

type IssuerDisplayEntry =
	NonNullable<
		NonNullable<CredentialConfigurationSupported["credential_metadata"]>["display"]
	>[number];

type DataUriResolverOptions = {
	httpClient: HttpClient;
	customRenderer: CustomCredentialSvgI;

	signedClaims?: Record<string, unknown>;

	credentialDisplayArray?: TypeDisplayEntry[];
	issuerDisplayArray?: IssuerDisplayEntry[];

	sdJwtVcRenderer?: CredentialRendering;
	sdJwtVcMetadataClaims?: ClaimMetadataEntry[];

	fallbackName?: string;
};
export function dataUriResolver({
	customRenderer,
	signedClaims = {},
	credentialDisplayArray,
	issuerDisplayArray,
	httpClient,
	sdJwtVcRenderer,
	sdJwtVcMetadataClaims,
	fallbackName = "Verifiable Credential",
}: DataUriResolverOptions): ImageDataUriCallback {
	return async (
		filter?: Array<CredentialClaimPath>,
		preferredLangs: string[] = ["en-US"],
		preferredProperties: SvgTemplateProperties = {
			orientation: "landscape",
			color_scheme: "light",
			contrast: "normal",
		}
	) => {
		try {
			// Localize display configs
			const credentialDisplayLocalized = matchDisplayByLocale(
				credentialDisplayArray,
				preferredLangs
			);
			const issuerDisplayLocalized = matchDisplayByLocale(
				issuerDisplayArray,
				preferredLangs
			);

			const svgTemplates =
				credentialDisplayLocalized?.rendering?.svg_templates ??
				issuerDisplayLocalized?.rendering?.svg_templates;
			const rankedSvgTemplates = rankSvgTemplates(svgTemplates, preferredProperties);

			const simpleDisplayConfig =
				credentialDisplayLocalized?.rendering?.simple || null;

			// 1. Try every SVG template in preference order
			if (sdJwtVcRenderer) {
				for (const svgTemplate of rankedSvgTemplates) {
					const credentialImageSvgTemplate = await loadSvgTemplate(svgTemplate.uri, httpClient);
					if (!credentialImageSvgTemplate) continue;

					const rendered = await sdJwtVcRenderer
						.renderSvgTemplate({
							json: signedClaims,
							credentialImageSvgTemplate,
							sdJwtVcMetadataClaims,
							filter,
						})
						.catch(() => null);

					if (rendered) return rendered;
				}
			}

			// 2. "simple" rendering from credential display (SD-JWT VC)
			if (simpleDisplayConfig && credentialDisplayLocalized) {
				const rendered = await customRenderer
					.renderCustomSvgTemplate({
						signedClaims,
						displayConfig: {
							...credentialDisplayLocalized,
							...simpleDisplayConfig,
						},
					})
					.catch(() => null);

				if (rendered) return rendered;
			}

			// 3. Fallback: render from issuer display
			if (issuerDisplayLocalized) {
				const rendered = await customRenderer
					.renderCustomSvgTemplate({
						signedClaims,
						displayConfig: issuerDisplayLocalized,
					})
					.catch(() => null);

				if (rendered) return rendered;
			}

			// 4. Final fallback
			return await customRenderer
				.renderCustomSvgTemplate({
					signedClaims,
					displayConfig: { name: fallbackName },
				})
				.catch(() => null);
		} catch {
			return null;
		}
	};
}
