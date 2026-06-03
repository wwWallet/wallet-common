import { z } from "zod";

export const ETSISDJWTVCSchema = z.object({
	iss: z.string().url({ message: "'iss' must be a valid URL" }),
	vct: z.string().min(1, { message: "'vct' is required" }),
	["vct#integrity"]: z.string({ message: "'vct#integrity' is required and must be valid" }),
	nbf: z.number({ message: "[ETSI TS 119 472-1: 5.7.2.1-01] 'nbf' is required" }),
	exp: z.number({ message: "[ETSI TS 119 472-1: 5.7.2.1-03] 'exp' is required" }),
	iat: z.number({ message: "[ETSI TS 119 472-1: 5.2.6-02] 'iat' is required" }),
	issuing_authority: z.string({ message: "[ETSI TS 119 472-1: 5.2.4.1-01] 'issuing_authority' is required" }),
	issuing_country: z.string({ message: "[ETSI TS 119 472-1: 5.2.4.1-04] 'issuing_country' is required" }),
	iss_reg_id: z.string().optional(),
	sub: z.string().optional(),
	also_known_as: z.string().optional(),
	given_name: z.string({ message: "[CIR 2024/2977 - Annex 1] 'given_name' is a mandatory field that must be available without selective disclosure." }),
	family_name: z.string({ message: "[CIR 2024/2977 - Annex 1] 'family_name' is a mandatory field that must be available without selective disclosure." }),
	birth_date: z.string({ message: "[CIR 2024/2977 - Annex 1] 'birth_date' is a mandatory field that must be available without selective disclosure." }),
	// birth_place: z.string()
	//   .min(1, { message: "[CIR 2024/2977 - Annex 1] 'birth_place' is a mandatory field that must be available without selective disclosure." })
	//   .max(2, { message: "[CIR 2024/2977 - Annex 1] 'birth_place' must be an alpha-2 country code as specified in ISO 3166-1." }),
	// nationality: z.string()
	//   .min(1, { message: "[CIR 2024/2977 - Annex 1] 'nationality' is a mandatory field that must be available without selective disclosure." })
	//   .max(2, { message: "[CIR 2024/2977 - Annex 1] 'nationality' must be an alpha-2 country code as specified in ISO 3166-1." }),
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
	.passthrough()
	.refine(
		(data) =>
			(typeof data.sub === "string") !==
			(typeof data.also_known_as === "string"),
		{
			message: "Exactly one of 'sub' or 'also_known_as' must be present",
			path: ["also_known_as"]
		}
	);

export type ETSISDJWTVC = z.infer<typeof ETSISDJWTVCSchema>;
