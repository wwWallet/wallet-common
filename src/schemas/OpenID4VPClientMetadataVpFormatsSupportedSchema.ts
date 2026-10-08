import { z } from 'zod';

export const JwtVcJsonSchema = z.object({
	alg_values: z.array(z.string()).nonempty().optional(),
});

export const LdpVcSchema = z.object({
	proof_type_values: z.array(z.string()).nonempty().optional(),
	cryptosuite_values: z.array(z.string()).nonempty().optional(),
});

export const MsoMdocSchema = z.object({
	issuerauth_alg_values: z.array(z.number()).nonempty().optional(),
	deviceauth_alg_values: z.array(z.number()).nonempty().optional(),
});

export const DcSdJwtSchema = z.object({
	'sd-jwt_alg_values': z.array(z.string()).nonempty().optional(),
	'kb-jwt_alg_values': z.array(z.string()).nonempty().optional(),
});

export const VpFormatsSupportedSchema = z.object({
	jwt_vc_json: JwtVcJsonSchema,
	ldp_vc: LdpVcSchema,
	mso_mdoc: MsoMdocSchema,
	'dc+sd-jwt': DcSdJwtSchema,
	'vc+sd-jwt': DcSdJwtSchema,
}).partial();

export type VpFormatsSupported = z.infer<typeof VpFormatsSupportedSchema>;
