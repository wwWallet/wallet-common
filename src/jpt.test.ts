import { assert, describe, it } from "vitest";

import { assembleIssuedJwp, assemblePresentationJwp, parseIssuedJwp, parsePresentedJwp } from "./jwp";
import { extractPayloadsFromClaims, extractClaimFromPayloads } from "./jpt";


const metadata = {
	"claims": [
		{ "path": ["iat"] },
		{ "path": ["family_name"] },
		{ "path": ["given_name"] },
		{ "path": ["birthdate"] },
		{ "path": ["place_of_birth"] },
		{ "path": ["place_of_birth", "locality"] },
		{ "path": ["place_of_birth", "region"] },
		{ "path": ["place_of_birth", "country"] },
		{ "path": ["nationalities", null] },
		{ "path": ["nationalities"] },
		{ "path": ["personal_administrative_number"] },
		{ "path": ["picture"] },
		{ "path": ["birth_family_name"] },
		{ "path": ["birth_given_name"] },
		{ "path": ["sex"] },
		{ "path": ["email"] },
		{ "path": ["phone_number"] },
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
		{ "path": ["age_in_years"] },
		{ "path": ["age_birth_year"] },
		{ "path": ["issuing_authority"] },
		{ "path": ["issuing_country"] },
		{ "path": ["date_of_expiry"] },
		{ "path": ["date_of_issuance"] },
		{ "path": ["document_number"] },
		{ "path": ["issuing_jurisdiction"] },
		{ "path": ["trust_anchor"] }
	],
};

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

	describe("extractClaimFromPayloads", () => {
		it("extracts primitive claims correctly.", () => {
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
			const jwp = assembleIssuedJwp({ alg: '' }, extractPayloadsFromClaims(claims, metadata), []);
			const { parsed: { payloads } } = parseIssuedJwp(jwp);
			assert.deepEqual(extractClaimFromPayloads(payloads, ["email"], metadata), { value: "a" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["iat"], metadata), { value: 42 });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["family_name"], metadata), { value: "bb" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_over_18"], metadata), { value: true });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nullfield"], metadata), { value: null });
		});

		it("extracts zero-length payloads as omitted claims.", () => {
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
			const jwp = assembleIssuedJwp({ alg: '' }, extractPayloadsFromClaims(claims, metadata), []);
			const { parsed: { payloads } } = parseIssuedJwp(jwp);
			assert.deepEqual(extractClaimFromPayloads(payloads, ["jti"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["sub"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["iat"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["family_name"], metadata), { value: "Testsson" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_over_18"], metadata), "not-found");
		});

		it("extracts null payloads as undisclosed claims.", () => {
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
			const issuedJwp = assembleIssuedJwp({ alg: '' }, extractPayloadsFromClaims(claims, metadata), []);
			const jwp = assemblePresentationJwp(issuedJwp, { alg: '' }, [3], []);
			const { parsed: { payloads } } = parsePresentedJwp(jwp);
			assert.deepEqual(extractClaimFromPayloads(payloads, ["jti"], metadata), "undisclosed");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["sub"], metadata), "undisclosed");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["iat"], metadata), "undisclosed");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["family_name"], metadata), { value: "Testsson" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_over_18"], metadata), "undisclosed");
		});

		it("throws an error for claim paths not present in metadata.", () => {
			const metadata = {
				"claims": [
					{ "path": ["jti"] },
					{ "path": ["sub"] },
					{ "path": ["iat"] },
					{ "path": ["family_name"] },
					{ "path": ["age_over_18"] },
					{ "path": ["address", "formatted"] },
					{ "path": ["nationalities", 0] },
					{ "path": ["nationalities", 1] },
					{ "path": ["nationalities", 3] },
				],
			};
			const claims = {
				family_name: "Testsson",
			};
			const issuedJwp = assembleIssuedJwp({ alg: '' }, extractPayloadsFromClaims(claims, metadata), []);
			const jwp = assemblePresentationJwp(issuedJwp, { alg: '' }, [3], []);
			const { parsed: { payloads } } = parsePresentedJwp(jwp);
			assert.throws(() => extractClaimFromPayloads(payloads, ["given_name"], metadata), /^Claim not found in metadata: /);
			assert.throws(() => extractClaimFromPayloads(payloads, ["address"], metadata), /^Claim not found in metadata: /);
			assert.throws(() => extractClaimFromPayloads(payloads, ["nationalities", 2], metadata), /^Claim not found in metadata: /);
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities", 0], metadata), "undisclosed");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities", 1], metadata), "undisclosed");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities", 3], metadata), "undisclosed");
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
			const jwp = assembleIssuedJwp({ alg: '' }, extractPayloadsFromClaims(claims, metadata), []);
			const { parsed: { payloads } } = parseIssuedJwp(jwp);
			assert.deepEqual(extractClaimFromPayloads(payloads, ["family_name"], metadata), { value: "Testsson" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address"], metadata), { value: { country: "SE", locality: "Stockholm" } });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address", "formatted"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address", "street_address"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address", "house_number"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address", "postal_code"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address", "locality"], metadata), { value: "Stockholm" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address", "region"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["address", "country"], metadata), { value: "SE" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_equal_or_over"], metadata), { value: { "14": true, "18": true, "65": false } });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_equal_or_over", "14"], metadata), { value: true });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_equal_or_over", "16"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_equal_or_over", "18"], metadata), { value: true });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_equal_or_over", "21"], metadata), "not-found");
			assert.deepEqual(extractClaimFromPayloads(payloads, ["age_equal_or_over", "65"], metadata), { value: false });
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
			const jwp = assembleIssuedJwp({ alg: '' }, extractPayloadsFromClaims(claims, metadata), []);
			const { parsed: { payloads } } = parseIssuedJwp(jwp);
			assert.deepEqual(extractClaimFromPayloads(payloads, ["family_name"], metadata), { value: "Testsson" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities", null], metadata), { value: ["GR", "SE"] });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities"], metadata), { value: ["GR", "SE"] });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities", 0], metadata), { value: "GR" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities", 1], metadata), { value: "SE" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["nationalities", 2], metadata), "not-found");
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
			const jwp = assembleIssuedJwp({ alg: '' }, extractPayloadsFromClaims(claims, metadata), []);
			const { parsed: { payloads } } = parseIssuedJwp(jwp);
			assert.deepEqual(extractClaimFromPayloads(payloads, ["family_name"], metadata), { value: "Testsson" });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["test/addresses", null, "country"], metadata), { value: ["GR", "SE"] });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["test/addresses", null, "locality"], metadata), { value: ["Αθήνα"] });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["test/addresses", null, "test/extra", 1, "foo"], metadata), { value: ["bar3"] });
			assert.deepEqual(extractClaimFromPayloads(payloads, ["test/addresses", null, "test/extra", null, "none"], metadata), { value: [] });
		});
	});
});
