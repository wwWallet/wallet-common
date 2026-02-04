import { z } from "zod";

export const SdJwtVcPayloadSchema = z
	.object({
		iss: z.string().url({ message: "'iss' must be a valid URL" }).optional(),
		iat: z.number().int().optional(),
		nbf: z.number().int().optional(),
		exp: z.number().int().optional(),
		vct: z.string().min(1, { message: "'vct' is required" }),
		cnf: z
			.object({
				jwk: z.record(z.any()).optional(),
			})
			.optional(),
		vc: z
			.object({
				"@context": z.array(z.string()).optional(),
				type: z.array(z.string()).optional(),
			})
			.optional(),
		_sd: z.array(z.string()).optional(),
		_sd_alg: z.string().optional(),
	})
	.passthrough(); // Allows any additional fields

export type SdJwtVcPayload = z.infer<typeof SdJwtVcPayloadSchema>;
