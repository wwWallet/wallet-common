import { describe, it, expect } from "vitest";
import { convertOpenid4vciToSdjwtvcClaims } from "./convertOpenid4vciToSdjwtvcClaims";
import type { OpenIdClaim } from "../schemas";

// Simple deep clone for tests
const deepClone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

describe("convertOpenid4vciToSdjwtvcClaims", () => {
	it("returns [] for undefined, null, or empty input", () => {
		expect(convertOpenid4vciToSdjwtvcClaims(undefined)).toEqual([]);
		expect(convertOpenid4vciToSdjwtvcClaims(null)).toEqual([]);
		expect(convertOpenid4vciToSdjwtvcClaims([])).toEqual([]);
	});

	it("maps display[].name → display[].label and trims locale/name", () => {
		const input = [
			{
				path: ["person", "name", "family"],
				display: [{ locale: "  en-US  ", name: "  Last name  " }],
			} as unknown as OpenIdClaim,
		];

		const out = convertOpenid4vciToSdjwtvcClaims(input);

		expect(out).toEqual([
			{
				path: ["person", "name", "family"],
				display: [{ locale: "en-US", label: "Last name" }],
			},
		]);
	});

	it("filters invalid display entries and omits display when none survive", () => {
		const input = [
			{
				path: ["id"],
				display: [
					{ locale: "", name: "no locale" },           // invalid
					{ locale: "en", name: "" },                  // invalid
					{ locale: "fr-FR" } as any,                  // invalid (no name)
					{} as any,                                   // invalid
					{ locale: " el-GR ", name: "  Ταυτότητα  " } // valid after trim
				],
			} as unknown as OpenIdClaim,
			{
				path: ["noDisplayAfterFilter"],
				display: [
					{ locale: "", name: "" },                    // invalid
					{ locale: " ", name: " " },                  // invalid
				],
			} as unknown as OpenIdClaim,
		];

		const out = convertOpenid4vciToSdjwtvcClaims(input);

		// First one keeps only the valid, trimmed Greek entry
		expect(out[0]).toEqual({
			path: ["id"],
			display: [{ locale: "el-GR", label: "Ταυτότητα" }],
		});

		// Second one must NOT include a display key at all
		expect(out[1]).toEqual({ path: ["noDisplayAfterFilter"] });
		expect(Object.prototype.hasOwnProperty.call(out[1], "display")).toBe(false);
	});

	it("preserves claim order", () => {
		const input = [
			{ path: ["a"], display: [{ locale: "en", name: "A" }] },
			{ path: ["b"] },
			{ path: ["c"], display: [{ locale: "en-US", name: "C" }] },
		].map(x => x as unknown as OpenIdClaim);

		const out = convertOpenid4vciToSdjwtvcClaims(input);

		expect(out.map(e => e.path.join("."))).toEqual(["a", "b", "c"]);
	});

	it("does not mutate the input array or its objects", () => {
		const original = [
			{
				path: ["immutable"],
				display: [{ locale: "en-US", name: "Immutable" }],
			} as unknown as OpenIdClaim,
		];
		const input = deepClone(original);

		const before = JSON.stringify(input);
		convertOpenid4vciToSdjwtvcClaims(input);
		const after = JSON.stringify(input);

		expect(after).toBe(before);
		expect(input).toEqual(original); // structure preserved
	});

	it("passes through path as-is (allows string | null | non-negative int per schema)", () => {
		const input = [
			{ path: ["person", "age"] } as unknown as OpenIdClaim,
			{ path: ["address", null, "street"] } as unknown as OpenIdClaim,   // includes null
			{ path: ["items", 0, "name"] } as unknown as OpenIdClaim,          // includes non-negative int
		];

		const out = convertOpenid4vciToSdjwtvcClaims(input);

		expect(out).toEqual([
			{ path: ["person", "age"] },
			{ path: ["address", null, "street"] },
			{ path: ["items", 0, "name"] },
		]);
	});

	it("ignores display entirely when input claim has no display", () => {
		const input = [
			{ path: ["noDisplay"] } as unknown as OpenIdClaim,
		];
		const out = convertOpenid4vciToSdjwtvcClaims(input);

		expect(out).toEqual([{ path: ["noDisplay"] }]);
		expect(Object.prototype.hasOwnProperty.call(out[0], "display")).toBe(false);
	});

	it("passes `mandatory` if present (true OR false), omits only when missing", () => {
		const input = [
			{
				path: ["must"],
				display: [{ locale: "en", name: "Must" }],
				mandatory: true,
			} as unknown as OpenIdClaim,
			{
				path: ["optional"],
				display: [{ locale: "en", name: "Optional" }],
				mandatory: false,
			} as unknown as OpenIdClaim,
			{
				path: ["unset"],
				display: [{ locale: "en", name: "Unset" }],
				// no mandatory field
			} as unknown as OpenIdClaim,
		];

		const out = convertOpenid4vciToSdjwtvcClaims(input);

		// TRUE: must be included
		expect(out[0]).toEqual({
			path: ["must"],
			display: [{ locale: "en", label: "Must" }],
			mandatory: true,
		});

		// FALSE: included because explicitly present
		expect(out[1]).toEqual({
			path: ["optional"],
			display: [{ locale: "en", label: "Optional" }],
			mandatory: false,
		});

		// MISSING: omitted entirely
		expect(out[2]).toEqual({
			path: ["unset"],
			display: [{ locale: "en", label: "Unset" }],
		});
		expect("mandatory" in out[2]).toBe(false);
	});

	it("handles mixed good/bad display entries and preserves valid ones", () => {
		const input = [
			{
				path: ["mixed"],
				display: [
					{ locale: "  en  ", name: "  Title  " }, // valid
					{ locale: "  ", name: "X" },            // invalid (blank locale)
					{ locale: "fr-FR", name: " " },         // invalid (blank name)
				],
			} as unknown as OpenIdClaim,
		];
		const out = convertOpenid4vciToSdjwtvcClaims(input);

		expect(out).toEqual([
			{
				path: ["mixed"],
				display: [{ locale: "en", label: "Title" }],
			},
		]);
	});

	it("works with many claims and ensures each output entry is a plain object with path", () => {
		const input: OpenIdClaim[] = Array.from({ length: 10 }, (_, i) => ({
			path: ["root", `key${i}`],
			display: i % 2 === 0 ? [{ locale: "en-US", name: `Key ${i}` }] : undefined,
			// toggle mandatory presence/values for variety
			...(i === 3 ? { mandatory: true } : {}),
			...(i === 4 ? { mandatory: false } : {}),
		})) as any;

		const out = convertOpenid4vciToSdjwtvcClaims(input);

		expect(out).toHaveLength(10);
		out.forEach((entry, i) => {
			expect(Array.isArray(entry.path)).toBe(true);
			expect(entry.path).toEqual(["root", `key${i}`]);

			if (i % 2 === 0) {
				expect(entry).toEqual(
					expect.objectContaining({
						display: [{ locale: "en-US", label: `Key ${i}` }],
					})
				);
			} else {
				expect(Object.prototype.hasOwnProperty.call(entry, "display")).toBe(false);
			}

			if (i === 3) {
				expect(entry).toEqual(expect.objectContaining({ mandatory: true }));
			} else if (i === 4) {
				expect(entry).toEqual(expect.objectContaining({ mandatory: false }));
			} else {
				expect("mandatory" in entry).toBe(false);
			}
		});
	});
});
