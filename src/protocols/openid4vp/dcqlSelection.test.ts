import { describe, expect, it } from "vitest";
import { validateDcqlCredentialSelection } from "./dcqlSelection";

const credentials = [{ id: "pid" }, { id: "degree" }, { id: "address" }];

describe("validateDcqlCredentialSelection", () => {
	it("requires every credential when credential_sets is absent", () => {
		expect(validateDcqlCredentialSelection({ credentials }, ["pid", "degree"])).toContain("address");
		expect(validateDcqlCredentialSelection({ credentials }, ["pid", "degree", "address"])).toBeNull();
	});

	it("accepts one complete option from a required credential set", () => {
		const query = { credentials, credential_sets: [{ options: [["pid"], ["degree", "address"]] }] };
		expect(validateDcqlCredentialSelection(query, ["pid"])).toBeNull();
		expect(validateDcqlCredentialSelection(query, ["degree", "address"])).toBeNull();
		expect(validateDcqlCredentialSelection(query, ["degree"])).toContain("required");
		expect(validateDcqlCredentialSelection(query, ["pid", "degree", "address"]))
			.toContain("alternative");
	});

	it("allows credentials from separate credential sets", () => {
		const query = {
			credentials,
			credential_sets: [
				{ options: [["pid"], ["degree"]] },
				{ options: [["address"]], required: false },
			],
		};
		expect(validateDcqlCredentialSelection(query, ["pid", "address"])).toBeNull();
	});

	it("allows an optional credential set to be omitted but not partially selected", () => {
		const query = {
			credentials,
			credential_sets: [
				{ options: [["pid"]] },
				{ options: [["degree", "address"]], required: false },
			],
		};
		expect(validateDcqlCredentialSelection(query, ["pid"])).toBeNull();
		expect(validateDcqlCredentialSelection(query, ["pid", "degree"])).toContain("partial");
		expect(validateDcqlCredentialSelection(query, ["pid", "degree", "address"])).toBeNull();
	});

	it("rejects unknown credential identifiers", () => {
		expect(validateDcqlCredentialSelection({ credentials }, ["pid", "unknown"])).toContain("unknown");
	});

	it("limits credential-set combination complexity", () => {
		const manyCredentials = Array.from({ length: 14 }, (_, index) => ({ id: `c${index}` }));
		manyCredentials.push({ id: "uncovered" });
		const credential_sets = manyCredentials.slice(0, -1).map(({ id }) => ({
			options: [[id]],
			required: false,
		}));
		expect(validateDcqlCredentialSelection(
			{ credentials: manyCredentials, credential_sets },
			manyCredentials.map(({ id }) => id)
		)).toContain("too complex");
	});
});
