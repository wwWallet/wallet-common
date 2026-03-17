import type { HttpClient, CredentialRendering, CustomCredentialSvgI } from "../interfaces";
import type { CredentialClaimPath, ImageDataUriCallback } from "../types";
import { matchDisplayByLocale } from "../utils/matchLocalizedDisplay";
import type { TypeDisplayEntry, ClaimMetadataEntry, SvgTemplateProperties, SvgTemplateEntry } from "../schemas/SdJwtVcTypeMetadataSchema";
import type { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

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

function pickBestSvgTemplate(
	templates: SvgTemplateEntry[] | undefined,
	properties: SvgTemplateProperties
): SvgTemplateEntry | null {
	if (!templates?.length) return null;
	if (templates.length === 1) return templates[0];

	const { orientation, color_scheme, contrast } = properties;

	let candidates = orientation
		? templates.filter((t) => t.properties?.orientation === orientation)
		: templates;

	if (!candidates.length) {
		candidates = templates;
	}

	if (color_scheme) {
		const colorMatches = candidates.filter(
			(t) => t.properties?.color_scheme === color_scheme
		);
		if (colorMatches.length) {
			candidates = colorMatches;
		}
	}

	if (contrast) {
		const contrastMatches = candidates.filter(
			(t) => t.properties?.contrast === contrast
		);
		if (contrastMatches.length) {
			candidates = contrastMatches;
		}
	}

	const withProperties = candidates.find((t) => t.properties);
	return withProperties ?? candidates[0] ?? templates[0];
}

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

			const svgTemplates = credentialDisplayLocalized?.rendering?.svg_templates;
			const selectedSvgTemplate = pickBestSvgTemplate(svgTemplates, preferredProperties);
			const svgTemplateUri = selectedSvgTemplate?.uri ?? null;

			const simpleDisplayConfig =
				credentialDisplayLocalized?.rendering?.simple || null;

			// 1. Try SVG template rendering (SD-JWT VC)
			if (svgTemplateUri && sdJwtVcRenderer) {
				let credentialImageSvgTemplate: string | undefined;

				if (svgTemplateUri.startsWith('data:')) {
					const res = await fetch(svgTemplateUri);
					const blob = await res.blob()

					if (blob.type === 'image/svg+xml') {
						const text = await blob.text();

						if (text && text !== '') {
							credentialImageSvgTemplate = text;
						}
					} else {
						console.warn(`Unsupported SVG template data URI type: ${blob.type}`);
					}
				} else if (svgTemplateUri.startsWith('http')) {
					const svgResponse = await httpClient
						.get(svgTemplateUri, {}, { useCache: true })
						.catch(() => null);

					if (svgResponse) {
						credentialImageSvgTemplate = svgResponse.data as string;
					}
				}

				if (credentialImageSvgTemplate) {
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
