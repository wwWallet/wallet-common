import { assert, describe, it } from "vitest";
import { MemoryStore } from "../../core/MemoryStore";
import { OpenID4VPClientAPI } from "./OpenID4VPClientAPI";
import { ResponseMode } from "./types";
import { generateKeyPair, exportPKCS8, exportJWK, CompactEncrypt } from "jose";
import { fromBase64Url, toBase64Url } from "../../utils/util";
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

describe("OpenID4VPClientAPI.generateAuthorizationRequestURL", () => {
	it("should build a valid URL, store rpState, and include DCQL in the request JWT", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const { privateKey } = await generateKeyPair("ES256");
		const privateKeyPem = await exportPKCS8(privateKey);

		const helper = new OpenID4VPClientAPI(
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

describe("OpenID4VPClientAPI small get/set helpers", () => {
	it("should save and load rpState by session id", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = {
			get: async () => {
				throw new Error("unexpected http call");
			}
		};

		const helper = new OpenID4VPClientAPI(
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

		const helper = new OpenID4VPClientAPI(
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

		const helper = new OpenID4VPClientAPI(
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

		const helper = new OpenID4VPClientAPI(
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

		const helper = new OpenID4VPClientAPI(
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

		const helper = new OpenID4VPClientAPI(
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

describe("OpenID4VPClientAPI.handleResponseDirectPost", () => {
	it("should store response details and mark completed", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = { get: async () => { throw new Error("unexpected http call"); } };

		const helper = new OpenID4VPClientAPI(
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
			session_id: "session-d",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-d",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-d",
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

		const vpToken = { pid: "vp" };
		const result = await helper.handleResponseDirectPost("session-d", vpToken, { id: "ps" });
		assert(result.ok === true);

		const stored = await helper.getRPStateBySessionId("session-d");
		assert(stored?.completed === true);
		assert(stored?.response_code);
		assert(stored?.presentation_submission?.id === "ps");
		assert(stored?.vp_token);

		const mapped = await kv.get(`response_code:${stored?.response_code}`);
		assert(mapped === "session-d");
	});

	it("should return errors for invalid inputs or state", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = { get: async () => { throw new Error("unexpected http call"); } };
		const helper = new OpenID4VPClientAPI(
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

		const missingState = await helper.handleResponseDirectPost(undefined, "vp", null);
		assert(missingState.ok === false);

		const missingVp = await helper.handleResponseDirectPost("state", undefined, null);
		assert(missingVp.ok === false);

		const missingRp = await helper.handleResponseDirectPost("missing", "vp", null);
		assert(missingRp.ok === false);

		const rpState = {
			session_id: "session-e",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-e",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-e",
			rp_eph_pub: { kty: "EC", crv: "P-256", x: "x", y: "y" },
			rp_eph_priv: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
			apv_jarm_encrypted_response_header: null,
			apu_jarm_encrypted_response_header: null,
			encrypted_response: null,
			vp_token: null,
			presentation_submission: null,
			response_code: null,
			claims: null,
			completed: true,
			presentation_during_issuance_session: null,
			date_created: Date.now()
		};
		await helper.saveRPState(rpState.session_id, rpState);

		const alreadyDone = await helper.handleResponseDirectPost("session-e", "vp", null);
		assert(alreadyDone.ok === false);
	});
});

describe("OpenID4VPClientAPI.handleResponseJARM", () => {
	it("should decrypt and store response details", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = { get: async () => { throw new Error("unexpected http call"); } };

		const helper = new OpenID4VPClientAPI(
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

		const { publicKey, privateKey } = await generateKeyPair("ECDH-ES");
		const rpEphPub = await exportJWK(publicKey);
		const rpEphPriv = await exportJWK(privateKey);
		rpEphPub.kid = "kid-jarm";
		rpEphPriv.kid = "kid-jarm";

		const rpState = {
			session_id: "session-j",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-j",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-jarm",
			rp_eph_pub: rpEphPub,
			rp_eph_priv: rpEphPriv,
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
		await kv.set("key:kid-jarm", rpState.session_id);

		const apu = toBase64Url(new TextEncoder().encode("apu"));
		const apv = toBase64Url(new TextEncoder().encode("apv"));
		const payload = { state: "session-j", vp_token: { pid: "vp" }, presentation_submission: { id: "ps" } };
		const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
			.setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
			.setKeyManagementParameters({ apu: new TextEncoder().encode("apu"), apv: new TextEncoder().encode("apv") })
			.encrypt(publicKey);

		const result = await helper.handleResponseJARM(jwe, "kid-jarm");
		assert(result.ok === true);

		const stored = await helper.getRPStateBySessionId("session-j");
		assert(stored?.completed === true);
		assert(stored?.response_code);
		assert(stored?.apu_jarm_encrypted_response_header === apu);
		assert(stored?.apv_jarm_encrypted_response_header === apv);
		assert(stored?.presentation_submission?.id === "ps");
		assert(stored?.vp_token);

		const mapped = await kv.get(`response_code:${stored?.response_code}`);
		assert(mapped === "session-j");
	});

	it("should return errors for missing state, missing vp_token, and completed session", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = { get: async () => { throw new Error("unexpected http call"); } };

		const helper = new OpenID4VPClientAPI(
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

		const { publicKey, privateKey } = await generateKeyPair("ECDH-ES");
		const rpEphPub = await exportJWK(publicKey);
		const rpEphPriv = await exportJWK(privateKey);
		rpEphPub.kid = "kid-jarm-2";
		rpEphPriv.kid = "kid-jarm-2";

		const rpState = {
			session_id: "session-j2",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-j2",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-jarm-2",
			rp_eph_pub: rpEphPub,
			rp_eph_priv: rpEphPriv,
			apv_jarm_encrypted_response_header: null,
			apu_jarm_encrypted_response_header: null,
			encrypted_response: null,
			vp_token: null,
			presentation_submission: null,
			response_code: null,
			claims: null,
			completed: true,
			presentation_during_issuance_session: null,
			date_created: Date.now()
		};

		await helper.saveRPState(rpState.session_id, rpState);
		await kv.set("key:kid-jarm-2", rpState.session_id);

		const payloadMissingState = { vp_token: { pid: "vp" }, presentation_submission: null };
		const jweMissingState = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payloadMissingState)))
			.setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
			.encrypt(publicKey);
		const missingState = await helper.handleResponseJARM(jweMissingState, "kid-jarm-2");
		assert(missingState.ok === false);

		const payloadMissingVp = { state: "session-j2", presentation_submission: null };
		const jweMissingVp = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payloadMissingVp)))
			.setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
			.encrypt(publicKey);
		const missingVp = await helper.handleResponseJARM(jweMissingVp, "kid-jarm-2");
		assert(missingVp.ok === false);

		const payloadOk = { state: "session-j2", vp_token: "vp", presentation_submission: null };
		const jweOk = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payloadOk)))
			.setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
			.encrypt(publicKey);
		const completed = await helper.handleResponseJARM(jweOk, "kid-jarm-2");
		assert(completed.ok === false);
	});

	it("should return error when rpState or decryption is missing/invalid", async () => {
		const kv = new MemoryStore<string, any>();
		const httpClient: HttpClient = { get: async () => { throw new Error("unexpected http call"); } };

		const helper = new OpenID4VPClientAPI(
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

		const missingRp = await helper.handleResponseJARM("invalid.jwe", "missing-kid");
		assert(missingRp.ok === false);

		const { publicKey, privateKey } = await generateKeyPair("ECDH-ES");
		const rpEphPub = await exportJWK(publicKey);
		const rpEphPriv = await exportJWK(privateKey);
		rpEphPub.kid = "kid-jarm-3";
		rpEphPriv.kid = "kid-jarm-3";

		const rpState = {
			session_id: "session-j3",
			is_cross_device: true,
			signed_request: "signed",
			state: "session-j3",
			nonce: "nonce",
			callback_endpoint: null,
			audience: "aud",
			presentation_request_id: "pid",
			presentation_definition: null,
			dcql_query: null,
			rp_eph_kid: "kid-jarm-3",
			rp_eph_pub: rpEphPub,
			rp_eph_priv: rpEphPriv,
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
		await kv.set("key:kid-jarm-3", rpState.session_id);

		const okPayload = { state: "session-j3", vp_token: "vp", presentation_submission: null };
		const okJwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(okPayload)))
			.setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
			.encrypt(publicKey);
		const tamperedJwe = okJwe.split(".").slice(0, 4).concat("invalid!").join(".");
		const decryptFail = await helper.handleResponseJARM(tamperedJwe, "kid-jarm-3");
		assert(decryptFail.ok === false);
	});
});
