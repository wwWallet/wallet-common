import { describe, expect, it } from "vitest";
import { imageValueToDataUri } from "./imageDataUri";

describe("imageValueToDataUri", () => {
	it("preserves supported image data URIs", () => {
		expect(imageValueToDataUri("data:image/jpeg;base64,/9j/AA=="))
			.toBe("data:image/jpeg;base64,/9j/AA==");
		const svgQrCode = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz48L3N2Zz4=";
		expect(imageValueToDataUri(svgQrCode)).toBe(svgQrCode);
	});

	it("converts encoded image bytes and serialized byte objects", () => {
		const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0x00]);
		expect(imageValueToDataUri(jpeg)).toBe("data:image/jpeg;base64,/9j/AA==");
		expect(imageValueToDataUri(new Uint8Array([1, ...jpeg, 2]).subarray(1, 5)))
			.toBe("data:image/jpeg;base64,/9j/AA==");
		expect(imageValueToDataUri({ 0: 0xff, 1: 0xd8, 2: 0xff, 3: 0x00 }))
			.toBe("data:image/jpeg;base64,/9j/AA==");
	});

	it("rejects unsafe or invalid data URIs and non-image bytes", () => {
		expect(imageValueToDataUri("data:image/svg+xml;base64,PHN2Zz48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+"))
			.toBeUndefined();
		expect(imageValueToDataUri("data:image/svg+xml;base64,PHN2Zz4="))
			.toBeUndefined();
		expect(imageValueToDataUri(new Uint8Array([1, 2, 3])))
			.toBeUndefined();
	});
});
