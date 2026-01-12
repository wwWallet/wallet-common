import type { TypeDisplayEntry } from "../schemas/SdJwtVcTypeMetadataSchema";
import type { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

type OpenIdCredentialDisplayEntry =
	NonNullable<CredentialConfigurationSupported["display"]>[number];

/**
 * Convert SD-JWT VC TypeMetadata.display -> OpenID4VCI CredentialConfigurationSupported.display
 *
 * Notes:
 * - svg_templates are intentionally ignored
 * - We map:
 *   - name -> name
 *   - description -> description
 *   - rendering.simple.background_color -> background_color
 *   - rendering.simple.text_color -> text_color
 *   - rendering.simple.background_image.uri -> background_image.uri
 *   - rendering.simple.logo -> logo
 *   - locale -> locale
 *
 */
export function convertSdjwtvcToOpenid4vciDisplay(
	display?: TypeDisplayEntry[]
): CredentialConfigurationSupported["display"] {
	if (!display?.length) return undefined;

	const byLocale = new Map<string, OpenIdCredentialDisplayEntry>();

	for (const d of display) {
		const simple = d.rendering?.simple;

		const candidate: OpenIdCredentialDisplayEntry = {
			name: d.name,
			description: d.description,
			locale: d.locale,

			background_color: simple?.background_color,
			text_color: simple?.text_color,

			...(simple?.background_image?.uri
				? { background_image: { uri: simple.background_image.uri } }
				: {}),

			...(simple?.logo?.uri
				? {
						logo: {
							uri: simple.logo.uri,
							alt_text: simple.logo.alt_text,
						},
				  }
				: {}),
		};

		// remove undefined keys (keeps output tidy)
		for (const key of Object.keys(candidate) as (keyof OpenIdCredentialDisplayEntry)[]) {
			if (candidate[key] === undefined) delete candidate[key];
		}

		const existing = byLocale.get(d.locale);
		if (!existing) {
			byLocale.set(d.locale, candidate);
			continue;
		}
	}

	return Array.from(byLocale.values());
}
