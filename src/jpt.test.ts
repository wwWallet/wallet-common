import { assert, describe, it } from "vitest";

import { assembleIssuedJwp } from "./jwp";
import { extractPayloadsFromClaims, parseJpt } from "./jpt";
import { toBase64Url } from "./utils/util";


describe("JPT payload encoding:", () => {
	describe("extractPayloadsFromClaims", () => {
		it("extracts primitive values correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["email"] },
					{ "path": ["iat"] },
					{ "path": ["family_name"] },
					{ "path": ["age_over_18"] },
					{ "path": ["nullfield"] },
				],
			};
			const claims = {
				email: "a",
				iat: 42,
				family_name: "bb",
				age_over_18: true,
				nullfield: null,
			};
			const payloads = extractPayloadsFromClaims(claims, metadata);
			const jwp = assembleIssuedJwp({ alg: '' }, payloads, []);
			assert.equal(jwp, 'eyJhbGciOiIifQ.ImEi~NDI~ImJiIg~dHJ1ZQ~bnVsbA.');
		});

		it("extracts claims in the order defined in metadata.", () => {
			const metadata = {
				"claims": [
					{ "path": ["email"] },
					{ "path": ["family_name"] },
				],
			};
			const claims = {
				family_name: "bb",
				email: "a",
			};
			const payloads = extractPayloadsFromClaims(claims, metadata);
			const jwp = assembleIssuedJwp({ alg: '' }, payloads, []);
			assert.equal(jwp, 'eyJhbGciOiIifQ.ImEi~ImJiIg.');
		});

		it("extracts nonexistent claims as a zero-length payload.", () => {
			const metadata = {
				"claims": [
					{ "path": ["jti"] },
					{ "path": ["sub"] },
					{ "path": ["iat"] },
					{ "path": ["family_name"] },
					{ "path": ["age_over_18"] },
				],
			};
			const claims = {
				family_name: "Testsson",
			};
			const payloads = extractPayloadsFromClaims(claims, metadata);
			const jwp = assembleIssuedJwp({ alg: '' }, payloads, []);
			assert.equal(jwp, 'eyJhbGciOiIifQ._~_~_~IlRlc3Rzc29uIg~_.');
		});

		it("does not extract claim values not selected by metadata.", () => {
			const metadata = {
				"claims": [
					{ "path": ["family_name"] },
				],
			};
			const claims = {
				email: "a",
				iat: 42,
				family_name: "bb",
				age_over_18: true,
				nullfield: null,
			};
			const payloads = extractPayloadsFromClaims(claims, metadata);
			const jwp = assembleIssuedJwp({ alg: '' }, payloads, []);
			assert.equal(jwp, 'eyJhbGciOiIifQ.ImJiIg.');
		});

		it("extracts object claims correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["family_name"] },
					{ "path": ["address"] },
					{ "path": ["address", "formatted"] },
					{ "path": ["address", "street_address"] },
					{ "path": ["address", "house_number"] },
					{ "path": ["address", "postal_code"] },
					{ "path": ["address", "locality"] },
					{ "path": ["address", "region"] },
					{ "path": ["address", "country"] },
					{ "path": ["age_equal_or_over"] },
					{ "path": ["age_equal_or_over", "14"] },
					{ "path": ["age_equal_or_over", "16"] },
					{ "path": ["age_equal_or_over", "18"] },
					{ "path": ["age_equal_or_over", "21"] },
					{ "path": ["age_equal_or_over", "65"] },
				],
			};
			const claims = {
				family_name: "Testsson",
				address: {
					country: "SE",
					locality: "Stockholm",
				},
				age_equal_or_over: {
					"14": true,
					"18": true,
					"65": false,
				},
			};
			const payloads = extractPayloadsFromClaims(claims, metadata);
			const jwp = assembleIssuedJwp({ alg: '' }, payloads, []);
			assert.equal(jwp, 'eyJhbGciOiIifQ.IlRlc3Rzc29uIg~eyJjb3VudHJ5IjoiU0UiLCJsb2NhbGl0eSI6IlN0b2NraG9sbSJ9~_~_~_~_~IlN0b2NraG9sbSI~_~IlNFIg~eyIxNCI6dHJ1ZSwiMTgiOnRydWUsIjY1IjpmYWxzZX0~dHJ1ZQ~_~dHJ1ZQ~_~ZmFsc2U.');
		});

		it("extracts array claims correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["family_name"] },
					{ "path": ["nationalities", null] },
					{ "path": ["nationalities"] },
					{ "path": ["nationalities", 0] },
					{ "path": ["nationalities", 1] },
					{ "path": ["nationalities", 2] },
				],
			};
			const claims = {
				family_name: "Testsson",
				nationalities: ['GR', 'SE'],
			};
			const payloads = extractPayloadsFromClaims(claims, metadata);
			const jwp = assembleIssuedJwp({ alg: '' }, payloads, []);
			assert.equal(jwp, 'eyJhbGciOiIifQ.IlRlc3Rzc29uIg~WyJHUiIsIlNFIl0~WyJHUiIsIlNFIl0~IkdSIg~IlNFIg~_.');
		});

		it("extracts complex claim paths correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["family_name"] },
					{ "path": ["test/addresses", null, "country"] },
					{ "path": ["test/addresses", null, "locality"] },
					{ "path": ["test/addresses", null, "test/extra", 1, "foo"] },
					{ "path": ["test/addresses", null, "test/extra", null, "none"] },
				],
			};
			const claims = {
				family_name: "Testsson",
				"test/addresses": [
					{ country: "GR", locality: "Αθήνα" },
					{ country: "SE", "test/extra": [{ foo: "bar", boo: "far" }] },
					{ "test/extra": [{ foo: "bar2", boo: "far2" }, { foo: "bar3", boo: "far3" }] },
					{ "test/extra": [{ foo: "bar4", boo: "far4" }, { boo: "far5" }] },
				],
			};
			const payloads = extractPayloadsFromClaims(claims, metadata);
			const jwp = assembleIssuedJwp({ alg: '' }, payloads, []);
			assert.equal(jwp, 'eyJhbGciOiIifQ.IlRlc3Rzc29uIg~WyJHUiIsIlNFIl0~WyLOkc64zq7Ovc6xIl0~WyJiYXIzIl0~W10.');
		});
	});

	describe("parseJpt", () => {
		it("parses primitive claims correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["email"] },
					{ "path": ["iat"] },
					{ "path": ["family_name"] },
					{ "path": ["age_over_18"] },
					{ "path": ["nullfield"] },
				],
			};
			const inputClaims = {
				email: "a",
				iat: 42,
				family_name: "bb",
				age_over_18: true,
				nullfield: null,
			};
			const header = { alg: '', vctm: [toBase64Url(new TextEncoder().encode(JSON.stringify(metadata)))] };
			const jwp = assembleIssuedJwp(header, extractPayloadsFromClaims(inputClaims, metadata), []);
			const { claims } = parseJpt(jwp);
			assert.deepEqual(claims, {
				simple: {
					email: "a",
					iat: 42,
					family_name: "bb",
					age_over_18: true,
					nullfield: null,
				},
				complex: [],
			});
		});

		it("parses zero-length payloads as omitted claims.", () => {
			const metadata = {
				"claims": [
					{ "path": ["jti"] },
					{ "path": ["sub"] },
					{ "path": ["iat"] },
					{ "path": ["family_name"] },
					{ "path": ["age_over_18"] },
				],
			};
			const inputClaims = {
				family_name: "Testsson",
			};
			const header = { alg: '', vctm: [toBase64Url(new TextEncoder().encode(JSON.stringify(metadata)))] };
			const jwp = assembleIssuedJwp(header, extractPayloadsFromClaims(inputClaims, metadata), []);
			const { claims } = parseJpt(jwp);
			assert.deepEqual(claims, {
				simple: { family_name: "Testsson", },
				complex: [],
			});
		});

		it("parses null payloads as undisclosed claims.", () => {
			const metadata = {
				"claims": [
					{ "path": ["jti"] },
					{ "path": ["sub"] },
					{ "path": ["iat"] },
					{ "path": ["family_name"] },
					{ "path": ["age_over_18"] },
				],
			};
			const inputClaims = {
				family_name: "Testsson",
			};
			const header = { alg: '', vctm: [toBase64Url(new TextEncoder().encode(JSON.stringify(metadata)))] };
			const jwp = assembleIssuedJwp(header, extractPayloadsFromClaims(inputClaims, metadata), []);
			const { claims } = parseJpt(jwp);
			assert.deepEqual(claims, {
				simple: { family_name: "Testsson", },
				complex: [],
			});
		});

		it("parses object claims correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["family_name"] },
					{ "path": ["address"] },
					{ "path": ["address", "formatted"] },
					{ "path": ["address", "street_address"] },
					{ "path": ["address", "house_number"] },
					{ "path": ["address", "postal_code"] },
					{ "path": ["address", "locality"] },
					{ "path": ["address", "region"] },
					{ "path": ["address", "country"] },
					{ "path": ["age_equal_or_over"] },
					{ "path": ["age_equal_or_over", "14"] },
					{ "path": ["age_equal_or_over", "16"] },
					{ "path": ["age_equal_or_over", "18"] },
					{ "path": ["age_equal_or_over", "21"] },
					{ "path": ["age_equal_or_over", "65"] },
				],
			};
			const inputClaims = {
				family_name: "Testsson",
				address: {
					country: "SE",
					locality: "Stockholm",
				},
				age_equal_or_over: {
					"14": true,
					"18": true,
					"65": false,
				},
			};
			const header = { alg: '', vctm: [toBase64Url(new TextEncoder().encode(JSON.stringify(metadata)))] };
			const jwp = assembleIssuedJwp(header, extractPayloadsFromClaims(inputClaims, metadata), []);
			const { claims } = parseJpt(jwp);
			assert.deepEqual(claims, {
				simple: {
					family_name: "Testsson",
					address: { country: "SE", locality: "Stockholm" },
					age_equal_or_over: { "14": true, "18": true, "65": false },
				},
				complex: [
					{ path: ["address", "locality"], value: "Stockholm" },
					{ path: ["address", "country"], value: "SE" },
					{ path: ["age_equal_or_over", "14"], value: true },
					{ path: ["age_equal_or_over", "18"], value: true },
					{ path: ["age_equal_or_over", "65"], value: false },
				],
			});
		});

		it("parses array claims correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["family_name"] },
					{ "path": ["nationalities", null] },
					{ "path": ["nationalities"] },
					{ "path": ["nationalities", 0] },
					{ "path": ["nationalities", 1] },
					{ "path": ["nationalities", 2] },
				],
			};
			const inputClaims = {
				family_name: "Testsson",
				nationalities: ['GR', 'SE'],
			};
			const header = { alg: '', vctm: [toBase64Url(new TextEncoder().encode(JSON.stringify(metadata)))] };
			const jwp = assembleIssuedJwp(header, extractPayloadsFromClaims(inputClaims, metadata), []);
			const { claims } = parseJpt(jwp);
			assert.deepEqual(claims, {
				simple: {
					family_name: "Testsson",
					nationalities: ["GR", "SE"],
				},
				complex: [
					{ path: ["nationalities", null], value: ["GR", "SE"] },
					{ path: ["nationalities", 0], value: "GR" },
					{ path: ["nationalities", 1], value: "SE" },
				],
			});
		});

		it("parses complex claim paths correctly.", () => {
			const metadata = {
				"claims": [
					{ "path": ["family_name"] },
					{ "path": ["test/addresses", null, "country"] },
					{ "path": ["test/addresses", null, "locality"] },
					{ "path": ["test/addresses", null, "test/extra", 1, "foo"] },
					{ "path": ["test/addresses", null, "test/extra", null, "none"] },
				],
			};
			const inputClaims = {
				family_name: "Testsson",
				"test/addresses": [
					{ country: "GR", locality: "Αθήνα" },
					{ country: "SE", "test/extra": [{ foo: "bar", boo: "far" }] },
					{ "test/extra": [{ foo: "bar2", boo: "far2" }, { foo: "bar3", boo: "far3" }] },
					{ "test/extra": [{ foo: "bar4", boo: "far4" }, { boo: "far5" }] },
				],
			};
			const header = { alg: '', vctm: [toBase64Url(new TextEncoder().encode(JSON.stringify(metadata)))] };
			const jwp = assembleIssuedJwp(header, extractPayloadsFromClaims(inputClaims, metadata), []);
			const { claims } = parseJpt(jwp);
			assert.deepEqual(claims, {
				simple: {
					family_name: "Testsson",
				},
				complex: [
					{ path: ["test/addresses", null, "country"], value: ["GR", "SE"] },
					{ path: ["test/addresses", null, "locality"], value: ["Αθήνα"] },
					{ path: ["test/addresses", null, "test/extra", 1, "foo"], value: ["bar3"] },
					{ path: ["test/addresses", null, "test/extra", null, "none"], value: [] },
				],
			});
		});
	});
});
