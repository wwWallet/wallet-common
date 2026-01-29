import { assert, describe, it } from "vitest";
import { MemoryStore } from "../../core/MemoryStore";
import { OpenID4VPHelper } from "./OpenID4VPHelper";
import { ResponseMode } from "./types";
import { generateKeyPair, exportPKCS8 } from "jose";
import { fromBase64Url } from "../../utils/util";
import type { HttpClient } from "../../interfaces";

const x5c = [
	"MIICyzCCAnGgAwIBAgIULnrxux9sI34oqbby3M4lSKOs8owwCgYIKoZIzj0EAwIwPzELMAkGA1UEBhMCRVUxFTATBgNVBAoMDHd3V2FsbGV0Lm9yZzEZMBcGA1UEAwwQd3dXYWxsZXQgUm9vdCBDQTAeFw0yNTA0MjkxMDI5NTNaFw0yNjA0MjkxMDI5NTNaMEExCzAJBgNVBAYTAkVVMRUwEwYDVQQKDAx3d1dhbGxldC5vcmcxGzAZBgNVBAMMEmxvY2FsLnd3d2FsbGV0Lm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFVivGt53M4qEP06QT20BSlGiMIdzLLvG+b9fq/fHKM+NGT+a3snXiPwU7X7jrOFWxwyjZeean40+vx6Gy06VfqjggFHMIIBQzAdBgNVHQ4EFgQUM/A3FTQLjww5/9u01MX/SRyVqaUwHwYDVR0jBBgwFoAU0HGu3T+/Wqh3yNifz9sNd+HPBS4wDgYDVR0PAQH/BAQDAgeAMDIGA1UdEgQrMCmBEWluZm9Ad3d3YWxsZXQub3JnhhRodHRwczovL3d3d2FsbGV0Lm9yZzASBgNVHSUECzAJBgcogYxdBQECMAwGA1UdEwEB/wQCMAAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cHM6Ly93d3dhbGxldC5vcmcvaWFjYS9jcmwvd3d3YWxsZXRfb3JnX2lhY2EuY3JsMFUGA1UdEQROMEyCEmxvY2FsLnd3d2FsbGV0Lm9yZ4IZbG9jYWwtaXNzdWVyLnd3d2FsbGV0Lm9yZ4IbbG9jYWwtdmVyaWZpZXIud3d3YWxsZXQub3JnMAoGCCqGSM49BAMCA0gAMEUCIQCQ8h+5krhO+f4woReDY1D7CaM6qCda3m814e6DLvOphAIgHQL+Wm7WFRwxgjzMLN37RojJGrZbF4OFChIkmm0uu5o="
];

const presentationRequest = {
	dcql_query: {
		credentials: [
			{
				id: "pidMsoMdoc",
				format: "mso_mdoc",
				meta: { doctype_value: "eu.europa.ec.eudi.pid.1" },
				claims: [
					{
						path: ["eu.europa.ec.eudi.pid.1", "family_name"],
						intent_to_retain: false
					}
				]
			}
		]
	}
};

describe("OpenID4VPHelper.generateAuthorizationRequestURL", () => {
	it("should build a valid URL, store rpState, and include DCQL in the request JWT", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const { privateKey } = await generateKeyPair("ES256");
		const privateKeyPem = await exportPKCS8(privateKey);

		const helper = new OpenID4VPHelper(
			kv,
			{
				credentialEngineOptions: {
					clockTolerance: 0,
					subtle: crypto.subtle,
					lang: "en",
					trustedCertificates: [],
					trustedCredentialIssuerIdentifiers: undefined
				},
				redirectUri: "openid4vp://cb"
			},
			httpClient
		);

		const responseUri = "https://verifier.example.com/cb";
		const baseUri = "https://verifier.example.com";
		const sessionId = "session-123";

		const result = await helper.generateAuthorizationRequestURL(
			presentationRequest,
			sessionId,
			responseUri,
			baseUri,
			privateKeyPem,
			x5c,
			ResponseMode.DIRECT_POST,
			"https://verifier.example.com/callback"
		);

		assert(result.stateId === sessionId);
		assert(result.url.protocol === "openid4vp:");
		assert(result.url.host === "cb");
		assert(result.url.searchParams.get("client_id") === "x509_san_dns:verifier.example.com");
		assert(result.url.searchParams.get("request_uri") === `${baseUri}/verification/request-object?id=${sessionId}`);

		const stored = await kv.get(`rpstate:${sessionId}`);
		assert(stored !== undefined);
		assert(stored.session_id === sessionId);
		assert(stored.nonce);
		assert(stored.signed_request);
		assert(stored.dcql_query !== null);
		assert(stored.completed === null);
		assert(await kv.get(`key:${stored.rp_eph_kid}`) === sessionId);

		const [encodedHeader, encodedPayload] = stored.signed_request.split(".");
		assert(encodedHeader && encodedPayload);
		const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(encodedPayload)));
		assert(payload.response_uri === responseUri);
		assert(payload.response_type === "vp_token");
		assert(payload.response_mode === ResponseMode.DIRECT_POST);
		assert(payload.state === sessionId);
		assert(payload.nonce);
		assert(payload.client_id === "x509_san_dns:verifier.example.com");
		assert(payload.dcql_query?.credentials?.[0]?.id === "pidMsoMdoc");
		assert(!("transaction_data" in payload));
		assert(payload.client_metadata?.jwks?.keys?.length === 1);
	});
});

describe("OpenID4VPHelper small get/set helpers", () => {
	it("should save and load rpState by session id", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const helper = new OpenID4VPHelper(
			kv,
			{
				credentialEngineOptions: {
					clockTolerance: 0,
					subtle: crypto.subtle,
					lang: "en",
					trustedCertificates: [],
					trustedCredentialIssuerIdentifiers: undefined
				},
				redirectUri: "openid4vp://cb"
			},
			httpClient
		);

		const rpState = {
			session_id: "session-a",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-a",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-a",
			rp_eph_pub: { kty: "EC", crv: "P-256", x: "x", y: "y" },
			rp_eph_priv: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
			apv_jarm_encrypted_response_header: null,
			apu_jarm_encrypted_response_header: null,
			encrypted_response: null,
			vp_token: null,
			presentation_submission: null,
			response_code: null,
			claims: null,
			completed: null,
			presentation_during_issuance_session: null,
			date_created: Date.now()
		};

		await helper.saveRPState(rpState.session_id, rpState);
		const loaded = await helper.getRPStateBySessionId("session-a");
		assert(loaded?.session_id === "session-a");
	});

	it("should return null when rpState is missing by session id", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const helper = new OpenID4VPHelper(
			kv,
			{
				credentialEngineOptions: {
					clockTolerance: 0,
					subtle: crypto.subtle,
					lang: "en",
					trustedCertificates: [],
					trustedCredentialIssuerIdentifiers: undefined
				},
				redirectUri: "openid4vp://cb"
			},
			httpClient
		);

		const loaded = await helper.getRPStateBySessionId("missing");
		assert(loaded === null);
	});

	it("should return null when rpState is missing by kid", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const helper = new OpenID4VPHelper(
			kv,
			{
				credentialEngineOptions: {
					clockTolerance: 0,
					subtle: crypto.subtle,
					lang: "en",
					trustedCertificates: [],
					trustedCredentialIssuerIdentifiers: undefined
				},
				redirectUri: "openid4vp://cb"
			},
			httpClient
		);

		const loaded = await helper.getRPStateByKid("missing-kid");
		assert(loaded === null);
	});

	it("should return rpState by kid when mapping exists", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const helper = new OpenID4VPHelper(
			kv,
			{
				credentialEngineOptions: {
					clockTolerance: 0,
					subtle: crypto.subtle,
					lang: "en",
					trustedCertificates: [],
					trustedCredentialIssuerIdentifiers: undefined
				},
				redirectUri: "openid4vp://cb"
			},
			httpClient
		);

		const rpState = {
			session_id: "session-b",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-b",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-b",
			rp_eph_pub: { kty: "EC", crv: "P-256", x: "x", y: "y" },
			rp_eph_priv: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
			apv_jarm_encrypted_response_header: null,
			apu_jarm_encrypted_response_header: null,
			encrypted_response: null,
			vp_token: null,
			presentation_submission: null,
			response_code: null,
			claims: null,
			completed: null,
			presentation_during_issuance_session: null,
			date_created: Date.now()
		};

		await helper.saveRPState(rpState.session_id, rpState);
		await kv.set("key:kid-b", rpState.session_id);

		const loaded = await helper.getRPStateByKid("kid-b");
		assert(loaded?.session_id === "session-b");
	});

	it("should return null when response code mapping is missing", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const helper = new OpenID4VPHelper(
			kv,
			{
				credentialEngineOptions: {
					clockTolerance: 0,
					subtle: crypto.subtle,
					lang: "en",
					trustedCertificates: [],
					trustedCredentialIssuerIdentifiers: undefined
				},
				redirectUri: "openid4vp://cb"
			},
			httpClient
		);

		const loaded = await helper.getRPStateByResponseCode("missing-code");
		assert(loaded === null);
	});

	it("should return rpState by response code when mapping exists", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const helper = new OpenID4VPHelper(
			kv,
			{
				credentialEngineOptions: {
					clockTolerance: 0,
					subtle: crypto.subtle,
					lang: "en",
					trustedCertificates: [],
					trustedCredentialIssuerIdentifiers: undefined
				},
				redirectUri: "openid4vp://cb"
			},
			httpClient
		);

		const rpState = {
			session_id: "session-c",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-c",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-c",
			rp_eph_pub: { kty: "EC", crv: "P-256", x: "x", y: "y" },
			rp_eph_priv: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
			apv_jarm_encrypted_response_header: null,
			apu_jarm_encrypted_response_header: null,
			encrypted_response: null,
			vp_token: null,
			presentation_submission: null,
			response_code: "resp-code",
			claims: null,
			completed: null,
			presentation_during_issuance_session: null,
			date_created: Date.now()
		};

		await helper.saveRPState(rpState.session_id, rpState);
		await kv.set("response_code:resp-code", rpState.session_id);

		const loaded = await helper.getRPStateByResponseCode("resp-code");
		assert(loaded?.session_id === "session-c");
	});
});
