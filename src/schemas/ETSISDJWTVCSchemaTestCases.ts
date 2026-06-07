import { z } from "zod";

export const ETSISDJWTVCMandatorySchema = z.object({
	vct: z.string().min(1, { message: "[ETSI TS 119 472-1] EAA-5.2.1.2-01: A SD-JWT VC EAA shall include the vct claim." }),
	["vct#integrity"]: z.string({ message: "[ETSI TS 119 472-1] EAA-5.2.1.2-03: A SD-JWT VC EAA shall incorporate the claim vct#integrity." }),
	nbf: z.number({ message: "[ETSI TS 119 472-1] EAA-5.2.7.1-01: A SD-JWT VC EAA shall include the nbf claim." }),
	exp: z.number({ message: "[ETSI TS 119 472-1] A SD-JWT VC EAA shall include the exp claim." }),
});

export const ETSISDJWTVCBaseSchema = ETSISDJWTVCMandatorySchema.extend({
	iss: z.string(),
	issuing_authority: z.string()
});

type Base = z.infer<typeof ETSISDJWTVCMandatorySchema>;

export type SjvEaaSchema = z.ZodType<
	Base & Record<string, any>,
	any,
	any
>;

export const CnfJwkSchema = z.object({
	cnf: z.object({
		jwk: z.record(z.any()).optional(),
	})
});

export const SjvEaaMandatorySchema = ETSISDJWTVCMandatorySchema
	.passthrough();

export const SjvEaa1Schema = ETSISDJWTVCBaseSchema
	.extend({
		given_name: z.string(),
		family_name: z.string()
	})
	.passthrough()
	.refine(
		(data) =>
			!(
				typeof data.sub === "string" &&
				typeof data.also_known_as === "string"
			),
		{
			message: "Only one of 'sub' or 'also_known_as' may be present",
			path: ["also_known_as"]
		}
	);

export const SjvEaa2Schema = ETSISDJWTVCBaseSchema
	.extend({
		sub: z.string(),
		given_name: z.string(),
		family_name: z.string(),
	})
	.passthrough()
	.and(CnfJwkSchema)
	.refine(
		(data) =>
			!(
				typeof data.sub === "string" &&
				typeof data.also_known_as === "string"
			),
		{
			message: "Only one of 'sub' or 'also_known_as' may be present",
			path: ["also_known_as"]
		}
	);

export const SjvEaa3Schema = ETSISDJWTVCBaseSchema
	.extend({
		issuing_country: z.string(),
		iss_reg_id: z.string(),
		sub: z.string(),
		given_name: z.string(),
		family_name: z.string()
	})
	.passthrough()
	.and(CnfJwkSchema)
	.refine(
		(data) =>
			!(
				typeof data.sub === "string" &&
				typeof data.also_known_as === "string"
			),
		{
			message: "Only one of 'sub' or 'also_known_as' may be present",
			path: ["also_known_as"]
		}
	);

export const SjvEaa4Schema = ETSISDJWTVCBaseSchema
	.extend({
		issuing_country: z.string(),
		iss_reg_id: z.string(),
		also_known_as: z.string()
	})
	.passthrough()
	.and(CnfJwkSchema)
	.refine(
		(data) =>
			!(
				typeof data.sub === "string" &&
				typeof data.also_known_as === "string"
			),
		{
			message: "Only one of 'sub' or 'also_known_as' may be present",
			path: ["also_known_as"]
		}
	);

export const SjvEaa5Schema = ETSISDJWTVCBaseSchema
	.extend({
		issuing_country: z.string(),
		iss_reg_id: z.string(),
		sub: z.string(),
		given_name: z.string(),
		family_name: z.string(),
		oneTime: z.null({ message: "[ETSI TS 119 472-1] EAA-5.2.8.2-05: The oneTime claim shall have the null JSON primitive type." })
	})
	.passthrough()
	.and(CnfJwkSchema)
	.refine(
		(data) =>
			!(
				typeof data.sub === "string" &&
				typeof data.also_known_as === "string"
			),
		{
			message: "Only one of 'sub' or 'also_known_as' may be present",
			path: ["also_known_as"]
		}
	);

export const SjvEaa6Schema = ETSISDJWTVCBaseSchema
	.extend({
		issuing_country: z.string(),
		iss_reg_id: z.string(),
		sub: z.string(),
		given_name: z.string(),
		family_name: z.string(),
		shortLived: z.null({ message: "[ETSI TS 119 472-1] EAA-5.2.12-02: The shortLived claim shall have the null JSON primitive type." })
	})
	.passthrough()
	.and(CnfJwkSchema)
	.refine(
		(data) =>
			!(
				typeof data.sub === "string" &&
				typeof data.also_known_as === "string"
			),
		{
			message: "Only one of 'sub' or 'also_known_as' may be present",
			path: ["also_known_as"]
		}
	);

export const SjvEaa7Schema = ETSISDJWTVCBaseSchema
	.extend({
		issuing_country: z.string(),
		iss_reg_id: z.string(),
		sub: z.string(),
		given_name: z.string(),
		family_name: z.string(),
		iat: z.number()
	})
	.passthrough()
	.and(CnfJwkSchema)
	.refine(
		(data) =>
			!(
				typeof data.sub === "string" &&
				typeof data.also_known_as === "string"
			),
		{
			message: "Only one of 'sub' or 'also_known_as' may be present",
			path: ["also_known_as"]
		}
	);

export const ETSISDJWTVCHeaderSchema = z.object({
	x5c: z.array(z.string()).min(1, {
		message: "[RFC 7515] The certificate or certificate chain \
is represented as a JSON array of \
base64-encoded certificate value strings." }),
	typ: z.literal("dc+sd-jwt", {
		message: "[SD-JWT VC] The Issuer MUST include \
the typ header parameter in the SD-JWT. \
The typ value MUST use dc+sd-jwt." }),
	alg: z.string()
		.refine((value) => value !== "none", {
			message: "[RFC 9901] alg: REQUIRED. \
A digital signature algorithm identifier. \
It MUST NOT be none."
		})
});

export const SjvEaaSchemaMap: Record<number, SjvEaaSchema> = {
	1: SjvEaa1Schema,
	2: SjvEaa2Schema,
	3: SjvEaa3Schema,
	4: SjvEaa4Schema,
	5: SjvEaa5Schema,
	6: SjvEaa6Schema,
	7: SjvEaa7Schema,
	8: SjvEaaMandatorySchema,
	9: SjvEaaMandatorySchema,
	10: SjvEaaMandatorySchema,
	11: SjvEaaMandatorySchema,
	12: SjvEaaMandatorySchema,
	13: SjvEaaMandatorySchema
} as const;

///

export enum DisclosureProfile {
	PROFILE_7 = "PROFILE_7",
	PROFILE_8 = "PROFILE_8",
	PROFILE_9 = "PROFILE_9",
	PROFILE_10 = "PROFILE_10",
	PROFILE_11 = "PROFILE_11",
	PROFILE_12 = "PROFILE_12",
	PROFILE_13 = "PROFILE_13"
}

export const SjvEaaDisclosureProfileMap: Record<number, DisclosureProfile> = {
	1: DisclosureProfile.PROFILE_7,
	2: DisclosureProfile.PROFILE_7,
	3: DisclosureProfile.PROFILE_7,
	4: DisclosureProfile.PROFILE_7,
	5: DisclosureProfile.PROFILE_7,
	6: DisclosureProfile.PROFILE_7,
	7: DisclosureProfile.PROFILE_7,
	8: DisclosureProfile.PROFILE_8,
	9: DisclosureProfile.PROFILE_9,
	10: DisclosureProfile.PROFILE_10,
	11: DisclosureProfile.PROFILE_11,
	12: DisclosureProfile.PROFILE_12,
	13: DisclosureProfile.PROFILE_13
} as const;

type DisclosurePolicy = {
	recursive: boolean | undefined;
	allowObjectProperties: boolean | undefined;
	allowArrayElements: boolean | undefined;
};

export const PROFILE_POLICIES: Record<
	DisclosureProfile,
	DisclosurePolicy
> = {
	[DisclosureProfile.PROFILE_7]: {
		recursive: false,
		allowObjectProperties: false,
		allowArrayElements: false
	},

	[DisclosureProfile.PROFILE_8]: {
		recursive: false,
		allowObjectProperties: true,
		allowArrayElements: false
	},

	[DisclosureProfile.PROFILE_9]: {
		recursive: false,
		allowObjectProperties: undefined,
		allowArrayElements: true
	},

	[DisclosureProfile.PROFILE_10]: {
		recursive: false,
		allowObjectProperties: true,
		allowArrayElements: true
	},

	[DisclosureProfile.PROFILE_11]: {
		recursive: true,
		allowObjectProperties: true,
		allowArrayElements: false
	},

	[DisclosureProfile.PROFILE_12]: {
		recursive: true,
		allowObjectProperties: undefined,
		allowArrayElements: true
	},

	[DisclosureProfile.PROFILE_13]: {
		recursive: true,
		allowObjectProperties: true,
		allowArrayElements: true
	}
};

export interface DisclosureAnalysis {
	hasObjectDisclosures: boolean;
	hasArrayElementDisclosures: boolean;

	hasRecursiveObjectDisclosures: boolean;
	hasRecursiveArrayDisclosures: boolean;
};

export function analyzeDisclosureStructure(
	payload: unknown,
	disclosures: unknown[]
): DisclosureAnalysis {

	const analysis: DisclosureAnalysis = {
		hasObjectDisclosures: false,
		hasArrayElementDisclosures: false,

		hasRecursiveObjectDisclosures: false,
		hasRecursiveArrayDisclosures: false
	};

	/**
	 * Walks a JSON structure looking for SD-JWT
	 * disclosure containers.
	 */
	function walk(
		value: unknown,
		callbacks: {
			onObjectDisclosure(): void;
			onArrayDisclosure(): void;
		}
	): void {

		if (
			value === null ||
			typeof value !== "object"
		) {
			return;
		}

		if (Array.isArray(value)) {

			for (const element of value) {

				if (
					element &&
					typeof element === "object" &&
					!Array.isArray(element) &&
					Object.hasOwn(element, "...")
				) {
					callbacks.onArrayDisclosure();
				}

				walk(element, callbacks);
			}

			return;
		}

		if (Object.hasOwn(value, "_sd")) {
			callbacks.onObjectDisclosure();
		}

		for (const child of Object.values(value)) {
			walk(child, callbacks);
		}
	}

	//
	// 1. Analyze issuer payload
	//

	walk(payload, {
		onObjectDisclosure() {
			analysis.hasObjectDisclosures = true;
		},
		onArrayDisclosure() {
			analysis.hasArrayElementDisclosures = true;
		}
	});

	//
	// 2. Analyze disclosed values for recursion
	//

	for (const disclosure of disclosures) {

		if (
			disclosure &&
			typeof disclosure === "object" &&
			"value" in disclosure
		) {

			walk(
				disclosure.value,
				{
					onObjectDisclosure() {
						analysis.hasRecursiveObjectDisclosures = true;
					},
					onArrayDisclosure() {
						analysis.hasRecursiveArrayDisclosures = true;
					}
				}
			);

			continue;
		}

		if (!Array.isArray(disclosure)) {
			continue;
		}

		//
		// Object-property disclosure:
		// [salt, claimName, claimValue]
		//

		if (disclosure.length === 3) {

			const disclosedValue = disclosure[2];

			walk(disclosedValue, {
				onObjectDisclosure() {
					analysis.hasRecursiveObjectDisclosures = true;
				},
				onArrayDisclosure() {
					analysis.hasRecursiveArrayDisclosures = true;
				}
			});
		}

		//
		// Array-element disclosure:
		// [salt, element]
		//

		else if (disclosure.length === 2) {

			const disclosedElement = disclosure[1];

			walk(disclosedElement, {
				onObjectDisclosure() {
					analysis.hasRecursiveObjectDisclosures = true;
				},
				onArrayDisclosure() {
					analysis.hasRecursiveArrayDisclosures = true;
				}
			});
		}
	}

	return analysis;
}

export function matchesProfile(
	analysis: DisclosureAnalysis,
	profile: DisclosureProfile
): boolean {

	switch (profile) {

		//
		// Profile #7
		// no selective disclosures
		//
		case DisclosureProfile.PROFILE_7:
			return (
				!analysis.hasObjectDisclosures &&
				!analysis.hasArrayElementDisclosures
			);

		//
		// Profile #8
		// non-recursive object disclosures only
		//
		case DisclosureProfile.PROFILE_8:

			// console.log(analysis);
			// console.log(analysis.hasObjectDisclosures);
			// console.log(!analysis.hasArrayElementDisclosures);
			// console.log(!analysis.hasRecursiveObjectDisclosures)

			return (
				analysis.hasObjectDisclosures &&
				!analysis.hasArrayElementDisclosures &&
				!analysis.hasRecursiveObjectDisclosures
			);

		//
		// Profile #9
		// non-recursive array element disclosures only
		//
		case DisclosureProfile.PROFILE_9:
			return (
				analysis.hasArrayElementDisclosures &&
				!analysis.hasRecursiveArrayDisclosures
			);

		//
		// Profile #10
		// non-recursive object + array disclosures
		//
		case DisclosureProfile.PROFILE_10:
			return (
				!analysis.hasRecursiveObjectDisclosures &&
				!analysis.hasRecursiveArrayDisclosures &&
				(
					analysis.hasObjectDisclosures ||
					analysis.hasArrayElementDisclosures
				)
			);

		//
		// Profile #11
		// recursive object disclosures only
		//
		case DisclosureProfile.PROFILE_11:
			return (
				analysis.hasObjectDisclosures &&
				analysis.hasRecursiveObjectDisclosures &&
				!analysis.hasArrayElementDisclosures
			);

		//
		// Profile #12
		// recursive array disclosures only
		//
		case DisclosureProfile.PROFILE_12:
			return (
				analysis.hasRecursiveArrayDisclosures
			);

		//
		// Profile #13
		// recursive object + array disclosures
		//
		case DisclosureProfile.PROFILE_13:
			return (
				analysis.hasObjectDisclosures ||
				analysis.hasArrayElementDisclosures
			);

		default:
			return false;
	}
}

export function decodeDisclosure(
	encoded: string
): unknown {

	const json =
		Buffer
			.from(
				encoded,
				"base64url"
			)
			.toString("utf8");

	return JSON.parse(json);
}
