import type {
	SvgTemplateEntry,
	SvgTemplateProperties,
} from "../schemas/SdJwtVcTypeMetadataSchema";

export function pickBestSvgTemplate(
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
