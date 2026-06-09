import { z } from 'zod';

export const JwtVcJsonSchema = z.object({
	alg_values: z.array(z.string()),
});

export const LdpVcSchema = z.object({
	proof_type_values: z.array(z.string()),
	cryptosuite_values: z.array(z.string()),
});

export const MsoMdocSchema = z.object({
	issuerauth_alg_values: z.array(z.number()),
	deviceauth_alg_values: z.array(z.number()),
});

export const DcSdJwtSchema = z.object({
	'sd-jwt_alg_values': z.array(z.string()),
	'kb-jwt_alg_values': z.array(z.string()),
});

export const VpFormatsSupportedSchema = z.object({
	jwt_vc_json: JwtVcJsonSchema.optional(),
	ldp_vc: LdpVcSchema.optional(),
	mso_mdoc: MsoMdocSchema.optional(),
	'dc+sd-jwt': DcSdJwtSchema.optional(),
});

export type VpFormatsSupported = z.infer<typeof VpFormatsSupportedSchema>;
