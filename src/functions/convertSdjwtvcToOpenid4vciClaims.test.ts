import { describe, it, expect } from "vitest";
import { convertSdjwtvcToOpenid4vciClaims } from "./convertSdjwtvcToOpenid4vciClaims";
import type { ClaimMetadataEntry } from "../schemas/SdJwtVcTypeMetadataSchema";

// deep clone helper
const deepClone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

describe("convertSdjwtvcToOpenid4vciClaims", () => {
	it("returns [] for undefined, null, or empty input", () => {
		expect(convertSdjwtvcToOpenid4vciClaims(undefined)).toEqual([]);
		expect(convertSdjwtvcToOpenid4vciClaims(null)).toEqual([]);
		expect(convertSdjwtvcToOpenid4vciClaims([])).toEqual([]);
	});

	it("maps display[].label → display[].name and trims", () => {
		const input: ClaimMetadataEntry[] = [
			{
				path: ["person", "name", "family"],
				display: [{ locale: "  en-US  ", label: "  Last name  " }],
			},
		];

		const out = convertSdjwtvcToOpenid4vciClaims(input);

		expect(out).toEqual([
			{
				path: ["person", "name", "family"],
				display: [{ locale: "en-US", name: "Last name" }],
			},
		]);
	});

	it("omits display if all entries invalid", () => {
		const input: ClaimMetadataEntry[] = [
			{
				path: ["id"],
				display: [
					{ locale: "", label: "bad" } as any,
					{ locale: "en", label: "" } as any,
				],
			},
		];

		const out = convertSdjwtvcToOpenid4vciClaims(input);

		expect(out).toEqual([{ path: ["id"] }]);
		expect("display" in out[0]).toBe(false);
	});

	it("passes mandatory if present (true OR false), omits only when missing", () => {
		const input: ClaimMetadataEntry[] = [
			{
				path: ["must"],
				display: [{ locale: "en", label: "Must" }],
				mandatory: true,
			},
			{
				path: ["optional"],
				display: [{ locale: "en", label: "Optional" }],
				mandatory: false,
			},
			{
				path: ["unset"],
				display: [{ locale: "en", label: "Unset" }],
			},
		];

		const out = convertSdjwtvcToOpenid4vciClaims(input);

		expect(out[0]).toEqual({
			path: ["must"],
			display: [{ locale: "en", name: "Must" }],
			mandatory: true,
		});

		expect(out[1]).toEqual({
			path: ["optional"],
			display: [{ locale: "en", name: "Optional" }],
			mandatory: false,
		});

		expect(out[2]).toEqual({
			path: ["unset"],
			display: [{ locale: "en", name: "Unset" }],
		});
		expect("mandatory" in out[2]).toBe(false);
	});

	it("does not mutate the input", () => {
		const input: ClaimMetadataEntry[] = [
			{
				path: ["immutable"],
				display: [{ locale: "en-US", label: "Immutable" }],
				mandatory: true,
			},
		];
		const clone = deepClone(input);

		convertSdjwtvcToOpenid4vciClaims(input);
		expect(input).toEqual(clone);
	});

	it("handles mixed path types (string|null|number)", () => {
		const input: ClaimMetadataEntry[] = [
			{ path: ["items", 0, "value"] },
			{ path: ["address", null, "city"] },
		];

		expect(convertSdjwtvcToOpenid4vciClaims(input)).toEqual([
			{ path: ["items", 0, "value"] },
			{ path: ["address", null, "city"] },
		]);
	});
});
