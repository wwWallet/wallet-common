import type {
	SvgTemplateEntry,
	SvgTemplateProperties,
} from "../schemas/SdJwtVcTypeMetadataSchema";

export function pickBestSvgTemplate(
	templates: SvgTemplateEntry[] | undefined,
	properties: SvgTemplateProperties
): SvgTemplateEntry | null {
	return rankSvgTemplates(templates, properties)[0] ?? null;
}

export function rankSvgTemplates(
	templates: SvgTemplateEntry[] | undefined,
	properties: SvgTemplateProperties
): SvgTemplateEntry[] {
	if (!templates?.length) return [];

	return templates
		.map((template, index) => ({
			template,
			index,
			score: getPreferenceScore(template, properties),
		}))
		.sort((a, b) => b.score - a.score || a.index - b.index)
		.map(({ template }) => template);
}

function getPreferenceScore(
	template: SvgTemplateEntry,
	properties: SvgTemplateProperties
): number {
	// Each preference outweighs every lower-priority match combined.
	let score = template.properties ? 1 : 0;

	if (
		properties.orientation &&
		template.properties?.orientation === properties.orientation
	) {
		score += 8;
	}
	if (
		properties.color_scheme &&
		template.properties?.color_scheme === properties.color_scheme
	) {
		score += 4;
	}
	if (
		properties.contrast &&
		template.properties?.contrast === properties.contrast
	) {
		score += 2;
	}

	return score;
}
