import { assert, describe, it } from "vitest";
import Crypto from "node:crypto";
import { Jwt, SDJwt } from "@sd-jwt/core";
import { OpenID4VPServerAPI } from "./OpenID4VPServerAPI";
import { ResponseMode } from "./types";
import { VerifiableCredentialFormat } from "../../types";

const issuerSignedB64U = `omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQS62BhZBLWnZnN0YXR1c6Frc3RhdHVzX2xpc3SiY2lkeBhsY3VyaXhWaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL3N0YXR1cy84ODc5M2MwMy0xNmFkLTQ0NjgtYmVmNy1jMDgzZDM4YWUyMTlnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNS0wMi0xOFQxNDoxMjowNFppdmFsaWRGcm9twHQyMDI1LTAyLTE4VDE0OjEyOjA0Wmp2YWxpZFVudGlswHQyMDI1LTAzLTA0VDE0OjEyOjA0Wmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xtgBYIKuGxnFMGhNio5-VUJKePlkmw33mloMA9fgqUR0ynOoJAVggWxNyUrVxTPW2riSGxx_U_irluD-vcJIOGGrafGo6JpwCWCDKOCdlxlbeX7mztFkzrM7MsZHs3gEyrmC79X3N2VpxkgNYICmI6iaQPBePM7fzBXqPyX5Gr-wNnWNCNb7wDUz4VDIRBFggfCuu8bFboi9BiRPsM447Ncg9A7K7A28iTEjVy9fmjBIFWCC6z1AlQM8ttJfuIQtPYlurlamh3MvAbSaQoUzAn-9L9gZYIKD1mVbZ5zb-_sp_E6vZCQ_U2QAQVNtbWAznR4xUm6LoB1ggWAn0OSPMM-m8NbgBZ-D6qLV0BEVeSnR4DIsUPUOZDbsIWCDyTDBH9XjK_JIq_W7d19UpmMq1pd1CjrmhfIHsctg3gwlYIK7ejRc3g-pfNGM0WHv4Oh1jfshl03Jvm3cxKHFnIIXmClggjPVDgZmiJEpnM6Zo_mzUQAbW5M6QZuRH43L6BqVeT7wLWCCSVNDu2CjnRkbC7_6m6-G6h8dTDWvlmGz0WD-MUCGERwxYIDpAXdFHgnACMgICXQpJi9nzBDRjsJ8bY1htM9GtgZlKDVggvhyWJk8WGQgokFghnd9DyZKyo8b6VrfAX8WTB0vH1QkOWCBLJFY_nbKL1x-5fbJCqS1IgEn_uMm9NJm2vqorCWwwPg9YIJIg7rTS_E3HAYjcjdV6WSpgZuXa8IKo7f5aC9ibPXQzEFggc_BlS8FdmjVtSqXrA2Xh58naoO0XdTbwclGo9itNTIERWCDzIo5muAIWaawEG69bUPG4mI4pEB5dUhadaUeMUEuwIhJYIEALsAqnwl3T1nC7YtOeDj-7OEHlmcwhCZjY2Qgsr2vCE1ggwG6In0GuGqO1isPXfh2EA7-mi18JAhfumCyQUA5FpYYUWCAL6kBisfFYUIU06t2d0UeqElM-c49VrVqfgYYSIx2JpRVYICYx93c95xCPFdhE03ZlReMnLGSjT_SJgEBMeErv0VlXbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgganiJYJ0goJBbFzWZ52BDtTvTP1Fqb6k80C4UBl6JrFwiWCCWf2o4RIOTRI_UGubc0rCyIDo-o_LYRzYRnWzos3gcSm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAcBP9-i1suGc_TnH7z4Mp8jFAz2Q__4w7Ju7dDG93XWfCE15E15WYaXUnkYY80tStLInk7nEi6IqEPHJPUyWiyGpuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMZbYGFhRpGZyYW5kb21Q6lwO6tOJcjKhPDMrRPrRFGhkaWdlc3RJRABsZWxlbWVudFZhbHVlGDxxZWxlbWVudElkZW50aWZpZXJsYWdlX2luX3llYXJz2BhYT6RmcmFuZG9tUBwuvU0MGGbT2h94xazpeqloZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhdpGZyYW5kb21Qo6kOsHqedb_9xHVlfCXHf2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZTUxMTQ3cWVsZW1lbnRJZGVudGlmaWVydHJlc2lkZW50X3Bvc3RhbF9jb2Rl2BhYVaRmcmFuZG9tUP6aK3BnaJ4ssYCnhgPSaZpoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWZCRVJMSU5xZWxlbWVudElkZW50aWZpZXJrYmlydGhfcGxhY2XYGFhPpGZyYW5kb21QGR_ZD_ylLFjp_gFyoXxR0WhkaWdlc3RJRARsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFWkZnJhbmRvbVByTlMf_mCOUvaECM5veox_aGRpZ2VzdElEBWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYY6RmcmFuZG9tUED3uH1EYolIFfAdQr8v6pVoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZcB0MTk2NC0wOC0xMlQwMDowMDowMFpxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWE-kZnJhbmRvbVBucDIRMDGt1bMXZVQopw3OaGRpZ2VzdElEB2xlbGVtZW50VmFsdWX0cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzY12BhYVqRmcmFuZG9tUEQqTillqXQcpIwC8F2YOMloZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMoKXZZ4ZDwVRRL4IQ7oDEFoZGlnZXN0SUQJbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTbYGFhXpGZyYW5kb21QdJ-5Oz_55VjO0LOBbnoLs2hkaWdlc3RJRApsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYa6RmcmFuZG9tUMexUIlyfvCgcIUu67OBH6doZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDItMThUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYVKRmcmFuZG9tUJ_7jstnoovdbm84Cmh2etFoZGlnZXN0SUQMbGVsZW1lbnRWYWx1ZRkHrHFlbGVtZW50SWRlbnRpZmllcm5hZ2VfYmlydGhfeWVhctgYWFmkZnJhbmRvbVAnc4IFpUS4gxjqo-1DsQNvaGRpZ2VzdElEDWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWE-kZnJhbmRvbVD0dq9e6pNoaa0e_tVlZ-hZaGRpZ2VzdElEDmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYU6RmcmFuZG9tUIurbtyPoiia4qsc62iQHIBoZGlnZXN0SUQPbGVsZW1lbnRWYWx1ZWVFUklLQXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tUKgfL0gkbSOApy2APkdkNatoZGlnZXN0SUQQbGVsZW1lbnRWYWx1ZXBIRUlERVNUUkHhup5FIDE3cWVsZW1lbnRJZGVudGlmaWVyb3Jlc2lkZW50X3N0cmVldNgYWFGkZnJhbmRvbVA3gWJEwZz8jgsLsfRJvjMQaGRpZ2VzdElEEWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJrbmF0aW9uYWxpdHnYGFhPpGZyYW5kb21QHSMBCaBxBPPy92dCcmoZvWhkaWdlc3RJRBJsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8yMdgYWFakZnJhbmRvbVB4Df01yH0SBmag1gS4xKL9aGRpZ2VzdElEE2xlbGVtZW50VmFsdWVlS8OWTE5xZWxlbWVudElkZW50aWZpZXJtcmVzaWRlbnRfY2l0edgYWFukZnJhbmRvbVDxOTqapogRuHVS1cLoK7z6aGRpZ2VzdElEFGxlbGVtZW50VmFsdWVmR0FCTEVScWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRo2BhYaaRmcmFuZG9tUOFMkL6pWaVejQQEv7_aS-loZGlnZXN0SUQVbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDMtMDRUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZQ`;
/**
Decoded issuerSignedB64U (for reference):
{
	"eu.europa.ec.eudi.pid.1": {
		"age_in_years": 60,
		"age_over_12": true,
		"resident_postal_code": "51147",
		"birth_place": "BERLIN",
		"age_over_14": true,
		"issuing_country": "DE",
		"birth_date": "August 12, 1964",
		"age_over_65": false,
		"resident_country": "DE",
		"age_over_16": true,
		"issuing_authority": "DE",
		"issuance_date": "February 18, 2025 at 14:12",
		"age_birth_year": 1964,
		"family_name": "MUSTERMANN",
		"age_over_18": true,
		"given_name": "ERIKA",
		"resident_street": "HEIDESTRAẞE 17",
		"nationality": "DE",
		"age_over_21": true,
		"resident_city": "KÖLN",
		"family_name_birth": "GABLER",
		"expiry_date": "March 4, 2025 at 14:12"
	}
}
*/

const buildSdJwt = async (payload: Record<string, unknown>) => {
	const { privateKey } = Crypto.generateKeyPairSync("ed25519");
	const signer = async (data: string) => {
		const sig = Crypto.sign(null, Buffer.from(data), privateKey);
		return Buffer.from(sig).toString("base64url");
	};
	const jwt = new Jwt({ header: { alg: "EdDSA" }, payload });
	await jwt.sign(signer);
	const sdJwt = new SDJwt({ jwt, disclosures: [] });
	return sdJwt.encodeSDJwt();
};

describe("OpenID4VPServerAPI.handleAuthorizationRequest", () => {
	it("should store rpState and return mapping for an sd-jwt DCQL query", async () => {
		const signedClaimsPid = { vct: "urn:eudi:pid:1", given_name: "Alice", family_name: "Doe" };
		const signedClaimsOther = { vct: "urn:eudi:ehic:1", given_name: "Bob" };
		const sdJwtPid = await buildSdJwt(signedClaimsPid);
		const sdJwtOther = await buildSdJwt(signedClaimsOther);
		const mdocPid = issuerSignedB64U;

		const storedState: { value: any | null } = { value: null };
		const helper = new OpenID4VPServerAPI({
			httpClient: { get: async () => { throw new Error("unexpected http call"); } },
			rpStateStore: {
				store: async (state) => { storedState.value = state; },
				retrieve: async () => storedState.value,
			},
			parseCredential: async (credential) => {
				if (credential.data === sdJwtPid) {
					return { signedClaims: signedClaimsPid };
				}
				if (credential.data === sdJwtOther) {
					return { signedClaims: signedClaimsOther };
				}
				return null;
			},
			selectCredentialForBatch: async () => null,
			keystore: {
				signJwtPresentation: async () => ({ vpjwt: "vp-jwt" }),
				generateDeviceResponse: async () => ({ deviceResponseMDoc: {} }),
			},
			strings: {
				purposeNotSpecified: "No purpose provided",
				allClaimsRequested: "All claims",
			},
		});

		const dcql_query = {
			credentials: [
				{
					id: "testCredential",
					format: VerifiableCredentialFormat.DC_SDJWT,
					meta: { vct_values: ["urn:eudi:pid:1"] },
					claims: [{ path: ["given_name"] }],
				},
			],
		};

		const url = new URL("openid4vp://authorize");
		url.searchParams.set("client_id", "x509_san_dns:verifier.example.com");
		url.searchParams.set("response_uri", "https://verifier.example.com/cb");
		url.searchParams.set("nonce", "nonce-123");
		url.searchParams.set("state", "state-123");
		url.searchParams.set("client_metadata", JSON.stringify({ vp_formats: {} }));
		url.searchParams.set("response_mode", JSON.stringify(ResponseMode.DIRECT_POST));
		url.searchParams.set("dcql_query", JSON.stringify(dcql_query));

		const vcEntityList = [
			{ format: VerifiableCredentialFormat.DC_SDJWT, data: sdJwtPid, batchId: 7, instanceId: 0 },
			{ format: VerifiableCredentialFormat.DC_SDJWT, data: sdJwtOther, batchId: 8, instanceId: 0 },
			{ format: VerifiableCredentialFormat.MSO_MDOC, data: mdocPid, batchId: 9, instanceId: 0 },
		];

		const result = await helper.handleAuthorizationRequest(url.toString(), vcEntityList);
		assert(!("error" in result));
		assert(result.parsedTransactionData === null);
		assert(result.verifierDomainName === "x509_san_dns:verifier.example.com");
		const entry = result.conformantCredentialsMap.get("testCredential");
		assert(entry?.credentials?.includes(7));
		assert(entry?.requestedFields?.some((f) => f.path?.join(".") === "given_name"));
		assert(storedState.value?.nonce === "nonce-123");
		assert(storedState.value?.response_mode === ResponseMode.DIRECT_POST);
		assert(Array.isArray(storedState.value?.transaction_data));
		assert(storedState.value?.transaction_data.length === 0);
	});

	it("should return mapping for an mso_mdoc DCQL query", async () => {
		const signedClaimsPid = { vct: "urn:eudi:pid:1", given_name: "Alice" };
		const sdJwtPid = await buildSdJwt(signedClaimsPid);
		const mdocPid = issuerSignedB64U;

		const storedState: { value: any | null } = { value: null };
		const helper = new OpenID4VPServerAPI({
			httpClient: { get: async () => { throw new Error("unexpected http call"); } },
			rpStateStore: {
				store: async (state) => { storedState.value = state; },
				retrieve: async () => storedState.value,
			},
			parseCredential: async () => ({ signedClaims: signedClaimsPid }),
			selectCredentialForBatch: async () => null,
			keystore: {
				signJwtPresentation: async () => ({ vpjwt: "vp-jwt" }),
				generateDeviceResponse: async () => ({ deviceResponseMDoc: {} }),
			},
			strings: {
				purposeNotSpecified: "No purpose provided",
				allClaimsRequested: "All claims",
			},
		});

		const dcql_query = {
			credentials: [
				{
					id: "pidMdoc",
					format: "mso_mdoc",
					meta: { doctype_value: "eu.europa.ec.eudi.pid.1" },
					claims: [{ path: ["eu.europa.ec.eudi.pid.1", "family_name"] }],
				},
			],
		};

		const url = new URL("openid4vp://authorize");
		url.searchParams.set("client_id", "x509_san_dns:verifier.example.com");
		url.searchParams.set("response_uri", "https://verifier.example.com/cb");
		url.searchParams.set("nonce", "nonce-456");
		url.searchParams.set("state", "state-456");
		url.searchParams.set("client_metadata", JSON.stringify({ vp_formats: {} }));
		url.searchParams.set("response_mode", JSON.stringify(ResponseMode.DIRECT_POST));
		url.searchParams.set("dcql_query", JSON.stringify(dcql_query));

		const vcEntityList = [
			{ format: VerifiableCredentialFormat.DC_SDJWT, data: sdJwtPid, batchId: 7, instanceId: 0 },
			{ format: VerifiableCredentialFormat.MSO_MDOC, data: mdocPid, batchId: 9, instanceId: 0 },
		];

		const result = await helper.handleAuthorizationRequest(url.toString(), vcEntityList);
		assert(!("error" in result));
		const entry = result.conformantCredentialsMap.get("pidMdoc");
		assert(entry?.credentials?.[0] === 9);
	});

	it("should return insufficient credentials when request asks for missing vct", async () => {
		const signedClaimsPid = { vct: "urn:eudi:pid:1", given_name: "Alice" };
		const sdJwtPid = await buildSdJwt(signedClaimsPid);
		const mdocPid = issuerSignedB64U;

		const helper = new OpenID4VPServerAPI({
			httpClient: { get: async () => { throw new Error("unexpected http call"); } },
			rpStateStore: {
				store: async () => {},
				retrieve: async () => ({}) as any,
			},
			parseCredential: async () => ({ signedClaims: signedClaimsPid }),
			selectCredentialForBatch: async () => null,
			keystore: {
				signJwtPresentation: async () => ({ vpjwt: "vp-jwt" }),
				generateDeviceResponse: async () => ({ deviceResponseMDoc: {} }),
			},
			strings: {
				purposeNotSpecified: "No purpose provided",
				allClaimsRequested: "All claims",
			},
		});

		const dcql_query = {
			credentials: [
				{
					id: "missingCredential",
					format: VerifiableCredentialFormat.DC_SDJWT,
					meta: { vct_values: ["urn:eudi:ehic:1"] },
					claims: [{ path: ["given_name"] }],
				},
			],
		};

		const url = new URL("openid4vp://authorize");
		url.searchParams.set("client_id", "x509_san_dns:verifier.example.com");
		url.searchParams.set("response_uri", "https://verifier.example.com/cb");
		url.searchParams.set("nonce", "nonce-789");
		url.searchParams.set("state", "state-789");
		url.searchParams.set("client_metadata", JSON.stringify({ vp_formats: {} }));
		url.searchParams.set("response_mode", JSON.stringify(ResponseMode.DIRECT_POST));
		url.searchParams.set("dcql_query", JSON.stringify(dcql_query));

		const vcEntityList = [
			{ format: VerifiableCredentialFormat.DC_SDJWT, data: sdJwtPid, batchId: 7, instanceId: 0 },
			{ format: VerifiableCredentialFormat.MSO_MDOC, data: mdocPid, batchId: 9, instanceId: 0 },
		];

		const result = await helper.handleAuthorizationRequest(url.toString(), vcEntityList);
		assert("error" in result);
		assert(result.error === "insufficient_credentials");
	});

	it("should return missing_dcql_query when dcql_query is omitted", async () => {
		const helper = new OpenID4VPServerAPI({
			httpClient: { get: async () => { throw new Error("unexpected http call"); } },
			rpStateStore: {
				store: async () => {},
				retrieve: async () => ({}) as any,
			},
			parseCredential: async () => null,
			selectCredentialForBatch: async () => null,
			keystore: {
				signJwtPresentation: async () => ({ vpjwt: "vp-jwt" }),
				generateDeviceResponse: async () => ({ deviceResponseMDoc: {} }),
			},
			strings: {
				purposeNotSpecified: "No purpose provided",
				allClaimsRequested: "All claims",
			},
		});

		const url = new URL("openid4vp://authorize");
		url.searchParams.set("client_id", "x509_san_dns:verifier.example.com");
		url.searchParams.set("response_uri", "https://verifier.example.com/cb");
		url.searchParams.set("nonce", "nonce-000");
		url.searchParams.set("state", "state-000");
		url.searchParams.set("client_metadata", JSON.stringify({ vp_formats: {} }));
		url.searchParams.set("response_mode", JSON.stringify(ResponseMode.DIRECT_POST));

		const result = await helper.handleAuthorizationRequest(url.toString(), []);
		assert("error" in result);
		assert(result.error === "missing_dcql_query");
	});

	it("should return non_supported_client_id_scheme for unsupported client_id", async () => {
		const helper = new OpenID4VPServerAPI({
			httpClient: { get: async () => { throw new Error("unexpected http call"); } },
			rpStateStore: {
				store: async () => {},
				retrieve: async () => ({}) as any,
			},
			parseCredential: async () => null,
			selectCredentialForBatch: async () => null,
			keystore: {
				signJwtPresentation: async () => ({ vpjwt: "vp-jwt" }),
				generateDeviceResponse: async () => ({ deviceResponseMDoc: {} }),
			},
			strings: {
				purposeNotSpecified: "No purpose provided",
				allClaimsRequested: "All claims",
			},
		});

		const dcql_query = {
			credentials: [
				{
					id: "testCredential",
					format: VerifiableCredentialFormat.DC_SDJWT,
					meta: { vct_values: ["urn:eudi:pid:1"] },
					claims: [{ path: ["given_name"] }],
				},
			],
		};

		const url = new URL("openid4vp://authorize");
		url.searchParams.set("client_id", "did:example:verifier");
		url.searchParams.set("response_uri", "https://verifier.example.com/cb");
		url.searchParams.set("nonce", "nonce-001");
		url.searchParams.set("state", "state-001");
		url.searchParams.set("client_metadata", JSON.stringify({ vp_formats: {} }));
		url.searchParams.set("response_mode", JSON.stringify(ResponseMode.DIRECT_POST));
		url.searchParams.set("dcql_query", JSON.stringify(dcql_query));

		const result = await helper.handleAuthorizationRequest(url.toString(), []);
		assert("error" in result);
		assert(result.error === "non_supported_client_id_scheme");
	});

	it("should return old_state when nonce was already used", async () => {
		const helper = new OpenID4VPServerAPI({
			httpClient: { get: async () => { throw new Error("unexpected http call"); } },
			rpStateStore: {
				store: async () => {},
				retrieve: async () => ({}) as any,
			},
			parseCredential: async () => null,
			selectCredentialForBatch: async () => null,
			keystore: {
				signJwtPresentation: async () => ({ vpjwt: "vp-jwt" }),
				generateDeviceResponse: async () => ({ deviceResponseMDoc: {} }),
			},
			strings: {
				purposeNotSpecified: "No purpose provided",
				allClaimsRequested: "All claims",
			},
			lastUsedNonceStore: {
				get: () => "nonce-reused",
				set: () => {},
			},
		});

		const dcql_query = {
			credentials: [
				{
					id: "testCredential",
					format: VerifiableCredentialFormat.DC_SDJWT,
					meta: { vct_values: ["urn:eudi:pid:1"] },
					claims: [{ path: ["given_name"] }],
				},
			],
		};

		const url = new URL("openid4vp://authorize");
		url.searchParams.set("client_id", "x509_san_dns:verifier.example.com");
		url.searchParams.set("response_uri", "https://verifier.example.com/cb");
		url.searchParams.set("nonce", "nonce-reused");
		url.searchParams.set("state", "state-002");
		url.searchParams.set("client_metadata", JSON.stringify({ vp_formats: {} }));
		url.searchParams.set("response_mode", JSON.stringify(ResponseMode.DIRECT_POST));
		url.searchParams.set("dcql_query", JSON.stringify(dcql_query));

		const result = await helper.handleAuthorizationRequest(url.toString(), []);
		assert("error" in result);
		assert(result.error === "old_state");
	});
});
