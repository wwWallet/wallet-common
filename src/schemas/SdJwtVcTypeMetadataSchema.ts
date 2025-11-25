import { z } from "zod";

/** Integrity string per W3C SRI, e.g., "sha256-<base64url>" */
export const IntegrityString = z.string().min(1);

export const Uri = z.string().url();

export const LocaleTag = z.string().min(1);

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

/** ---------- §8.1.2 "svg_templates" rendering ---------- */
export const RenderingSimple = z.object({
	logo: LogoMetadata.optional(),
	background_image: z.object({
		uri: Uri,
		["uri#integrity"]: IntegrityString.optional(),
	}).optional(),
	background_color: z.string().optional(), // CSS color; keep as string
	text_color: z.string().optional(),       // CSS color; keep as string
});

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

const Rendering = z.object({
	simple: RenderingSimple.optional(),
	svg_templates: z.array(SvgTemplateEntry).optional(), // optional here
}).superRefine((val, ctx) => {
	const arr = val.svg_templates;
	if (arr && arr.length > 1) {
		arr.forEach((t, i) => {
			if (!t.properties) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `rendering.svg_templates[${i}].properties is required when more than one template is present`,
					path: ["svg_templates", i, "properties"],
				});
			}
		});
	}
});

/** ---------- §8 Display metadata for the TYPE ---------- */
export const TypeDisplayEntry = z.object({
	locale: LocaleTag,                 // REQUIRED
	name: z.string().min(1),       // REQUIRED
	description: z.string().optional(),
	rendering: Rendering.optional(),
});

/** ---------- §9.2 Display metadata for CLAIMS ---------- */
export const ClaimDisplayEntry = z.object({
	locale: LocaleTag,                 // REQUIRED
	label: z.string().min(1),      // REQUIRED
	description: z.string().optional(),
});

/** ---------- §9 Claim metadata entry ---------- */
export const ClaimMetadataEntry = z.object({
	path: ClaimPath,                                                    // REQUIRED
	display: z.array(ClaimDisplayEntry).optional(),                     // §9.2
	mandatory: z.boolean().optional(),                                  // §9.3 d12
	sd: z.enum(["always", "allowed", "never"]).optional(),              // §9.3 (default "allowed")
	svg_id: SvgId.optional(),                                           // §8.1.2.2
});

/** ---------- §6.2 Type Metadata Document ---------- */
export const TypeMetadata = z.object({
	vct: z.string(),
	name: z.string().optional(),
	description: z.string().optional(),

	extends: z.string().optional(),
	["extends#integrity"]: IntegrityString.optional(),

	display: z.array(TypeDisplayEntry).optional(),      // §8
	claims: z.array(ClaimMetadataEntry).optional(),     // §9

	// §7 integrity for the vct reference when used
	["vct#integrity"]: IntegrityString.optional(),
})
	.strip() // remove unknown fields but don't error
	.superRefine((val, ctx) => {
		const ids = new Set<string>();
		val.claims?.forEach((c, i) => {
			if (c.svg_id) {
				if (ids.has(c.svg_id)) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: `svg_id "${c.svg_id}" must be unique within the type metadata`,
						path: ["claims", i, "svg_id"],
					});
				}
				ids.add(c.svg_id);
			}
		});
	});

/** ---------- Exported Types ---------- */
export type TypeMetadata = z.infer<typeof TypeMetadata>;
export type ClaimMetadataEntry = z.infer<typeof ClaimMetadataEntry>;
export type TypeDisplayEntry = z.infer<typeof TypeDisplayEntry>;
export type ClaimDisplayEntry = z.infer<typeof ClaimDisplayEntry>;
export type ClaimPath = z.infer<typeof ClaimPath>;
export type SvgTemplateEntry = z.infer<typeof SvgTemplateEntry>;
