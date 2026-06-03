import { HasherAndAlg } from "@sd-jwt/types";
import { describe, expect, it } from "vitest";
import { HashAlgorithm } from "../types";
import { SDJwt } from "@sd-jwt/core";
import fs from "node:fs";

enum DisclosureProfile {
	PROFILE_1_7 = "PROFILE_1_7",
	PROFILE_7 = "PROFILE_7",
	PROFILE_8 = "PROFILE_8",
	PROFILE_9 = "PROFILE_9",
	PROFILE_10 = "PROFILE_10",
	PROFILE_11 = "PROFILE_11",
	PROFILE_12 = "PROFILE_12",
	PROFILE_13 = "PROFILE_13"
}

type DisclosureAnalysis = {
	hasObjectDisclosures: boolean;
	hasArrayElementDisclosures: boolean;

	hasRecursiveObjectDisclosures: boolean;
	hasRecursiveArrayDisclosures: boolean;
};

export function analyzeDisclosureStructure(
	payload: unknown
) {

	const analysis = {
		hasObjectDisclosures: false,
		hasArrayElementDisclosures: false,

		hasRecursiveObjectDisclosures: false,
		hasRecursiveArrayDisclosures: false
	};

	function walk(
		value: any,
		isRoot: boolean,
		path: string
	) {

		if (
			value &&
			typeof value === "object"
		) {

			if ("_sd" in value) {

				console.log("FOUND _sd AT:", path);

				analysis.hasObjectDisclosures = true;

				if (!isRoot) {

					console.log(
						"RECURSIVE _sd DETECTED AT:",
						path
					);

					analysis.hasRecursiveObjectDisclosures = true;
				}
			}

			if (Array.isArray(value)) {

				for (let i = 0; i < value.length; i++) {

					walk(
						value[i],
						false,
						`${path}[${i}]`
					);
				}

				return;
			}

			for (const [key, child] of Object.entries(value)) {

				if (key === "_sd") {
					continue;
				}

				walk(
					child,
					false,
					path
						? `${path}.${key}`
						: key
				);
			}
		}
	}

	walk(payload, true, "$");

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
				!analysis.hasObjectDisclosures &&
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
				analysis.hasArrayElementDisclosures &&
				!analysis.hasObjectDisclosures
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

const encoder = new TextEncoder();

// Encoding the string into a Uint8Array
const hasherAndAlgorithm: HasherAndAlg = {
	hasher: async (data: string | ArrayBuffer, alg: string) => {
		const encoded =
			typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);

		const v = await crypto.subtle.digest(alg, encoded);
		return new Uint8Array(v);
	},
	alg: HashAlgorithm.sha_256,
};

describe("ETSI SD-JWT VC disclosure profile validation", () => {

	it("should match Profile #7 when no selective disclosures exist", async () => {

		const payload = {
			sub: "12345",
			given_name: "Alice",
			family_name: "Doe",
			iss: "https://issuer.example.com",
			iat: 1710000000,
			exp: 1810000000
		};

		const analysis =
			analyzeDisclosureStructure(payload);
		console.log(analysis);

		const result =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_7
			);

		expect(result).toBe(true);

		expect(analysis).toEqual({
			hasObjectDisclosures: false,
			hasArrayElementDisclosures: false,

			hasRecursiveObjectDisclosures: false,
			hasRecursiveArrayDisclosures: false
		});
	});

	it("should match Profile #8 when object selective disclosures exist", async () => {

		const credential = fs.readFileSync("src/schemas/input/SJV-EAA-8.json", "utf8");

		const parsedCredential = await SDJwt.fromEncode(credential, hasherAndAlgorithm.hasher);

		const header = parsedCredential.jwt?.header;
		const payload = parsedCredential.jwt?.payload;

		const analysis =
			analyzeDisclosureStructure(payload);
		console.log(analysis);

		const result =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_8
			);

		expect(result).toBe(true);

		expect(analysis.hasObjectDisclosures)
			.toBe(true);
	});

	it("should match Profile #9 when object selective disclosures exist", async () => {

		const credential = fs.readFileSync("src/schemas/input/SJV-EAA-9.json", "utf8");

		const parsedCredential = await SDJwt.fromEncode(credential, hasherAndAlgorithm.hasher);

		const header = parsedCredential.jwt?.header;
		const payload = parsedCredential.jwt?.payload;

		const analysis =
			analyzeDisclosureStructure(payload);
		console.log(analysis);


		const result7 =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_7
			);

		const result8 =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_8
			);

		const result9 =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_9
			);

		const result10 =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_10
			);

		const result11 =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_11
			);

		const result12 =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_12
			);

		const result13 =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_13
			);

		console.log(result7, result8, result9, result10, result11, result12, result13);

		expect(result9).toBe(true);

		expect(analysis.hasObjectDisclosures)
			.toBe(true);
	});

	it("should match Profile #10 when object selective disclosures exist", async () => {

		const credential = fs.readFileSync("src/schemas/input/SJV-EAA-10.json", "utf8");

		const parsedCredential = await SDJwt.fromEncode(credential, hasherAndAlgorithm.hasher);

		const header = parsedCredential.jwt?.header;
		const payload = parsedCredential.jwt?.payload;

		const analysis =
			analyzeDisclosureStructure(payload);
		console.log(analysis);

		const result =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_10
			);

		expect(result).toBe(true);

		expect(analysis.hasObjectDisclosures)
			.toBe(true);
	});

	it("should match Profile #11 when object selective disclosures exist", async () => {

		const credential = fs.readFileSync("src/schemas/input/SJV-EAA-11.json", "utf8");

		const parsedCredential = await SDJwt.fromEncode(credential, hasherAndAlgorithm.hasher);

		const header = parsedCredential.jwt?.header;
		const payload = parsedCredential.jwt?.payload;

		const analysis =
			analyzeDisclosureStructure(payload);
		console.log(analysis);

		const result =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_11
			);

		expect(result).toBe(true);

		expect(analysis.hasObjectDisclosures)
			.toBe(true);
	});

	it("should match Profile #12 when object selective disclosures exist", async () => {

		const credential = fs.readFileSync("src/schemas/input/SJV-EAA-12.json", "utf8");

		const parsedCredential = await SDJwt.fromEncode(credential, hasherAndAlgorithm.hasher);

		const header = parsedCredential.jwt?.header;
		const payload = parsedCredential.jwt?.payload;

		const analysis =
			analyzeDisclosureStructure(payload);
		console.log(analysis);

		const result =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_12
			);

		expect(result).toBe(true);

		expect(analysis.hasObjectDisclosures)
			.toBe(true);
	});

	it("should match Profile #13 when object selective disclosures exist", async () => {

		const credential = fs.readFileSync("src/schemas/input/SJV-EAA-13.json", "utf8");

		const parsedCredential = await SDJwt.fromEncode(credential, hasherAndAlgorithm.hasher);

		const header = parsedCredential.jwt?.header;
		const payload = parsedCredential.jwt?.payload;

		const analysis =
			analyzeDisclosureStructure(payload);
		console.log(analysis);

		const result =
			matchesProfile(
				analysis,
				DisclosureProfile.PROFILE_13
			);

		expect(result).toBe(true);

		expect(analysis.hasObjectDisclosures)
			.toBe(true);
	});

});
