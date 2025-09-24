import { z } from 'zod';

/** display item */
const SdJwtVcDisplaySchema = z.object({
	lang: z.string().optional(),
	label: z.string().optional(),
});

/** a single SD-JWT VC claim */
const SdJwtVcClaimSchema = z.object({
	path: z.array(z.string().nullable()),
	display: z.array(SdJwtVcDisplaySchema).optional(),
});

export type SdJwtVcClaim = z.infer<typeof SdJwtVcClaimSchema>;
