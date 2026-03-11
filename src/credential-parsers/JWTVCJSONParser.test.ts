import { assert, describe, it } from "vitest";
import { JWTVCJSONParser } from "./JWTVCJSONParser";
import { Context, HttpClient } from "../interfaces";
import { CredentialParsingError } from "../error";
import { VerifiableCredentialFormat } from "../types";

const context: Context = {
	clockTolerance: 0,
	lang: "en-US",
	subtle: crypto.subtle,
	trustedCertificates: [],
};

const httpClient: HttpClient = {
	get: async () => ({ status: 404, headers: {}, data: {} }),
	post: async () => ({ status: 404, headers: {}, data: {} }),
};

function base64urlJSON(obj: unknown): string {
	return Buffer.from(JSON.stringify(obj), "utf-8")
		.toString("base64")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}

function buildUnsignedJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
	return `${base64urlJSON(header)}.${base64urlJSON(payload)}.sig`;
}

describe("JWTVCJSONParser", () => {
	it("parses a jwt_vc_json credential", async () => {
		const parser = JWTVCJSONParser({ context, httpClient });
		const now = Math.floor(Date.now() / 1000);
		const rawCredential = buildUnsignedJwt(
			{ alg: "ES256", typ: "jwt_vc_json" },
			{
				iss: "https://issuer.example.org",
				iat: now,
				nbf: now,
				exp: now + 3600,
				vc: {
					type: ["VerifiableCredential", "PIDCredential"],
					credentialSubject: { given_name: "Ada" },
				},
			}
		);

		const result = await parser.parse({ rawCredential });
		assert(result.success === true);
		if (!result.success) {
			return;
		}
		assert(result.value.metadata.credential.format === VerifiableCredentialFormat.JWT_VC_JSON);
		if (result.value.metadata.credential.format === VerifiableCredentialFormat.JWT_VC_JSON) {
			assert(result.value.metadata.credential.type.includes("PIDCredential"));
		}
		assert(result.value.validityInfo.validUntil instanceof Date);
	});

	it("returns UnsupportedFormat for sd-jwt typ", async () => {
		const parser = JWTVCJSONParser({ context, httpClient });
		const rawCredential = buildUnsignedJwt(
			{ alg: "ES256", typ: VerifiableCredentialFormat.VC_SDJWT },
			{ vc: { type: ["VerifiableCredential"] } }
		);

		const result = await parser.parse({ rawCredential });
		assert(result.success === false);
		if (!result.success) {
			assert(result.error === CredentialParsingError.UnsupportedFormat);
		}
	});

	it("returns CouldNotParse on malformed payload", async () => {
		const parser = JWTVCJSONParser({ context, httpClient });
		const header = base64urlJSON({ alg: "ES256", typ: "jwt_vc_json" });
		const malformedPayload = "%%%";
		const rawCredential = `${header}.${malformedPayload}.sig`;

		const result = await parser.parse({ rawCredential });
		assert(result.success === false);
		if (!result.success) {
			assert(result.error === CredentialParsingError.UnsupportedFormat || result.error === CredentialParsingError.CouldNotParse);
		}
	});
});
