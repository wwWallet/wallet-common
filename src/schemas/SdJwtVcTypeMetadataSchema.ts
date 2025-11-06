import { z } from "zod";

/** Integrity string per W3C SRI, e.g., "sha256-<base64url>" */
export const IntegrityString = z.string().min(1);

export const Uri = z.string().url();

export const LangTag = z.string().min(1);

/** Claim path per §9.1: array of string | null | non-negative integer */
export const ClaimPath = z.array(
	z.union([z.string(), z.null(), z.number().int().nonnegative()])
).nonempty();

/** svg_id: [A-Za-z_][A-Za-z0-9_]* per §8.1.2.2 */
export const SvgId = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);

/** ---------- §8.1.1 "simple" rendering ---------- */
export const LogoMetadata = z.object({
	uri: Uri,                              // REQUIRED
	["uri#integrity"]: IntegrityString.optional(),
	alt_text: z.string().optional(),
});

export const RenderingSimple = z.object({
	logo: LogoMetadata.optional(),
	background_color: z.string().optional(), // CSS color; keep as string
	text_color: z.string().optional(),       // CSS color; keep as string
});

/** ---------- §8.1.2 "svg_template" rendering ---------- */
export const SvgTemplateProperties = z.object({
	orientation: z.enum(["portrait", "landscape"]).optional(),
	color_scheme: z.enum(["light", "dark"]).optional(),
	contrast: z.enum(["normal", "high"]).optional(),
}).refine(
	(o) => o.orientation !== undefined || o.color_scheme !== undefined || o.contrast !== undefined,
	{ message: "svg_template.properties must contain at least one of orientation, color_scheme, contrast" }
);

export const SvgTemplateEntry = z.object({
	uri: Uri,                                // REQUIRED
	["uri#integrity"]: IntegrityString.optional(),
	properties: SvgTemplateProperties.optional(), // REQUIRED if >1 template; enforced at array level
});

export const RenderingSvgTemplate = z.object({
	svg_template: z.array(SvgTemplateEntry).min(1),
}).superRefine((val, ctx) => {
	if (val.svg_template.length > 1) {
		for (const [i, t] of val.svg_template.entries()) {
			if (!t.properties) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `svg_template[${i}].properties is required when more than one template is present`,
					path: ["svg_template", i, "properties"],
				});
			}
		}
	}
});

/** ---------- §8 Display metadata for the TYPE ---------- */
export const TypeDisplayEntry = z.object({
	lang: LangTag,                 // REQUIRED
	name: z.string().min(1),       // REQUIRED
	description: z.string().optional(),
	rendering: z.object({
		simple: RenderingSimple.optional(),
		// When present, put array under the same "rendering" object
		// keeping method identifiers as keys.
		svg_template: z.array(SvgTemplateEntry).min(1).optional(),
	}).optional()
});

/** ---------- §9.2 Display metadata for CLAIMS ---------- */
export const ClaimDisplayEntry = z.object({
	lang: LangTag,                 // REQUIRED
	label: z.string().min(1),      // REQUIRED
	description: z.string().optional(),
});

/** ---------- §9 Claim metadata entry ---------- */
export const ClaimMetadataEntry = z.object({
	path: ClaimPath,                                                    // REQUIRED
	display: z.array(ClaimDisplayEntry).optional(),                     // §9.2
	sd: z.enum(["always", "allowed", "never"]).optional(),              // §9.3 (default "allowed")
	svg_id: SvgId.optional(),                                           // §8.1.2.2
});

/** ---------- §6.2 Type Metadata Document ---------- */
export const TypeMetadata = z.object({
	// Not listed as REQUIRED in §6.2 table, but examples include it; keep optional for flexibility.
	vct: z.string().optional(),                         // §6.1 example shows "vct" in the doc
	name: z.string().optional(),
	description: z.string().optional(),

	extends: z.string().optional(),
	["extends#integrity"]: IntegrityString.optional(),

	display: z.array(TypeDisplayEntry).optional(),      // §8
	claims: z.array(ClaimMetadataEntry).optional(),     // §9

	// §7 integrity for the vct reference when used
	["vct#integrity"]: IntegrityString.optional(),
});

/** ---------- Exported Types ---------- */
export type TypeMetadata = z.infer<typeof TypeMetadata>;
export type ClaimMetadataEntry = z.infer<typeof ClaimMetadataEntry>;
export type TypeDisplayEntry = z.infer<typeof TypeDisplayEntry>;
export type ClaimDisplayEntry = z.infer<typeof ClaimDisplayEntry>;
export type ClaimPath = z.infer<typeof ClaimPath>;
export type SvgTemplateEntry = z.infer<typeof SvgTemplateEntry>;
