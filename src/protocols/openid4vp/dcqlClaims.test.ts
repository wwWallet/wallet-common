import { describe, expect, it } from "vitest";
import { generatePresentationFrameForDCQLPaths } from "./dcqlClaims";

const claims = {
	addresses: [
		{ street: "First", city: "Athens" },
		{ street: "Second", city: "Patras" },
	],
};

describe("generatePresentationFrameForDCQLPaths", () => {
	it("supports numeric array selectors", () => {
		expect(generatePresentationFrameForDCQLPaths(
			[["addresses", 1, "street"]],
			claims
		)).toEqual({ addresses: { 1: { street: true } } });
	});

	it("expands null selectors over every array element", () => {
		expect(generatePresentationFrameForDCQLPaths(
			[["addresses", null, "street"]],
			claims
		)).toEqual({
			addresses: {
				0: { street: true },
				1: { street: true },
			},
		});
	});

	it("rejects selectors that do not match the credential", () => {
		expect(() => generatePresentationFrameForDCQLPaths(
			[["addresses", 2, "street"]],
			claims
		)).toThrow("does not exist");
	});
});
