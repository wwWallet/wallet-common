import { describe, it, expect } from "vitest";
import { getSdJwtVcMetadata } from "./getSdJwtVcMetadata";
import { Context, HttpClient } from "../interfaces";
import { defaultHttpClient } from "../defaultHttpClient";


import crypto from "crypto";

export function generateSRIFromObject(obj: Record<string, any>, algorithm: "sha256" | "sha384" | "sha512" = "sha256"): string {
	const jsonString = JSON.stringify(obj);
	const hash = crypto.createHash(algorithm).update(jsonString, "utf8").digest("base64");
	return `${algorithm}-${hash}`;
}

const encodeBase64Url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

const context: Context = {
	clockTolerance: 0,
	lang: "en-US",
	subtle: crypto.subtle,
	trustedCertificates: []
};

const parentMetadata = {
	vct: "https://issuer.com/parent.json",
	display: [{ lang: "en-US", name: "Parent Credential", description: "This is the parent metadata." }],
	claims: [{ path: ["parent_id"], sd: "always", display: [{ lang: "en-US", label: "Parent ID" }] }]
};

const parentIntegrity = generateSRIFromObject(parentMetadata);

const childMetadata = {
	vct: "https://issuer.com/child.json",
	extends: "https://issuer.com/parent.json",
	"extends#integrity": parentIntegrity,
	display: [{ lang: "en-US", name: "Child Credential", description: "This is the child metadata." }],
	claims: [{ path: ["child_id"], sd: "always", display: [{ lang: "en-US", label: "Child ID" }] }]
};

const childIntegrity = "sha256-ilSsfKQ7sIAV8o2aXWOxzotWG6mJNK8TwemSpdFB57k=";

const validPayload = {
	iss: "https://issuer.com",
	vct: "https://issuer.com/child.json",
	"vct#integrity": childIntegrity
};


describe("getSdJwtVcMetadata - header failure cases", () => {


	it("fails on malformed base64 header", async () => {
		const malformedCredential = "!!notbase64!!.payload.sig"; // invalid base64

		const result = await getSdJwtVcMetadata(
			context,
			defaultHttpClient,
			malformedCredential,
			{} // doesn't matter for this test
		);

		expect(result).toMatchObject({ error: "HEADER_FAIL" });
	});

	it("fails on non-object header", async () => {
		const badHeader = btoa('"notAnObject"');
		const credential = `${badHeader}.payload.sig`;

		const result = await getSdJwtVcMetadata(
			context,
			defaultHttpClient,
			credential,
			{}
		);

		expect(result).toMatchObject({ error: "HEADER_FAIL" });
	});
});

describe("getSdJwtVcMetadata - payload failure cases", () => {
	it("fails when parsed claims are null", async () => {
		const validHeader = encodeBase64Url({ alg: "ES256" });
		const credential = `${validHeader}.payload.sig`;

		const result = await getSdJwtVcMetadata(
			context,
			defaultHttpClient,
			credential,
			null as any // simulate corrupted or missing parsedClaims
		);

		expect(result).toMatchObject({ error: "PAYLOAD_FAIL" });
	});

	it("fails when parsed claims are not an object", async () => {
		const validHeader = encodeBase64Url({ alg: "ES256" });
		const credential = `${validHeader}.payload.sig`;

		const result = await getSdJwtVcMetadata(
			context,
			defaultHttpClient,
			credential,
			"not-an-object" as any
		);

		expect(result).toMatchObject({ error: "PAYLOAD_FAIL" });
	});

	it("fails when parsed claims are missing `iss`", async () => {
		const validHeader = encodeBase64Url({ alg: "ES256" });
		const credential = `${validHeader}.payload.sig`;

		const result = await getSdJwtVcMetadata(
			context,
			defaultHttpClient,
			credential,
			{ vct: "https://example.com/vct.json" } // missing 'iss'
		);

		expect(result).toMatchObject({ error: "PAYLOAD_FAIL" });
	});
});

describe("getSdJwtVcMetadata - vct url failure cases", () => {
	function createHttpClient({
		childMetadataOverride,
		parentMetadataOverride,
		wellKnownIssuer = "https://issuer.com",
		failChild = false,
		failParent = false
	}: {
		childMetadataOverride?: object;
		parentMetadataOverride?: object;
		wellKnownIssuer?: string;
		failChild?: boolean;
		failParent?: boolean;
	} = {}): HttpClient {
		return {
			get: async (url: string) => {
				const baseResponse = { headers: {} };

				if (url.endsWith("/.well-known/jwt-vc-issuer")) {
					return { status: 200, data: { issuer: wellKnownIssuer }, ...baseResponse };
				}

				if (url.endsWith("child.json")) {
					if (failChild) return { status: 404, data: null };
					return {
						status: 200,
						data: childMetadataOverride || childMetadata,
						...baseResponse
					};
				}

				if (url.endsWith("parent.json")) {
					if (failParent) return { status: 404, data: null };
					return {
						status: 200,
						data: parentMetadataOverride || parentMetadata,
						...baseResponse
					};
				}

				return { status: 404, data: null, ...baseResponse };
			},
			post: async () => {
				throw new Error("POST not implemented");
			}
		};
	}


	it("warning on /jwt-vc-issuer mismatch", async () => {
		const payload = { ...validPayload, iss: "https://attacker.com" };
		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;
		const result = await getSdJwtVcMetadata(context, createHttpClient(), credential, payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'JWT_VC_ISSUER_MISMATCH')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});


	it("warning when fetching main vct fails", async () => {
		const payload = { ...validPayload };
		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({ failChild: true });

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'NOT_FOUND')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

	it("warning when fetching parent metadata (extends) fails", async () => {
		const payload = { ...validPayload };
		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({
			childMetadataOverride: {
				...childMetadata,
				extends: "https://issuer.com/parent.json",
				"extends#integrity": parentIntegrity
			},
			failParent: true
		});

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'NOT_FOUND')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

	it("fails with INFINITE_RECURSION when metadata extends each other", async () => {
		const circularParent = {
			...parentMetadata,
			extends: "https://issuer.com/child.json"
		};

		// Generate integrity for parent with the circular extend
		const circularParentIntegrity = generateSRIFromObject(circularParent);

		const circularChild = {
			...childMetadata,
			extends: "https://issuer.com/parent.json",
			"extends#integrity": circularParentIntegrity
		};

		const circularChildIntegrity = generateSRIFromObject(circularChild);

		const payload = {
			iss: "https://issuer.com",
			vct: "https://issuer.com/child.json",
			"vct#integrity": circularChildIntegrity
		};

		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({
			childMetadataOverride: circularChild,
			parentMetadataOverride: circularParent,
		});

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		expect(result).toMatchObject({ error: "INFINITE_RECURSION" });
	});


	it("warning on incorrect vct#integrity", async () => {
		const badIntegrity = "sha256-invalidhash===";

		const payload = {
			iss: "https://issuer.com",
			vct: "https://issuer.com/child.json",
			"vct#integrity": badIntegrity // invalid SRI that won't match actual data
		};

		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({
			childMetadataOverride: childMetadata
		});

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'INTEGRITY_FAIL')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

	it("fails with SCHEMA_FETCH_FAIL when schema_uri cannot be fetched", async () => {
		const childWithSchemaUri = {
			...childMetadata,
			schema_uri: "https://issuer.com/schema.json",
			"schema_uri#integrity": "sha256-invalid" // won't matter, fetch fails first
		};

		const childHash = generateSRIFromObject(childWithSchemaUri);

		const payload = {
			iss: "https://issuer.com",
			vct: "https://issuer.com/child.json",
			"vct#integrity": childHash
		};

		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({
			childMetadataOverride: childWithSchemaUri,
			failParent: false
		});

		httpClient.get = async (url: string) => {
			if (url.endsWith("/.well-known/jwt-vc-issuer")) {
				return { status: 200, data: { issuer: "https://issuer.com" } };
			}
			if (url.endsWith("child.json")) {
				return { status: 200, data: childWithSchemaUri };
			}
			if (url.endsWith("schema.json")) {
				return { status: 404, data: null };
			}
			return { status: 404, data: null };
		};

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		expect(result).toMatchObject({ error: "SCHEMA_FETCH_FAIL" });
	});


	it("fails with SCHEMA_CONFLICT when both schema and schema_uri are present", async () => {
		const conflictingMetadata = {
			...childMetadata,
			schema_uri: "https://issuer.com/schema.json",
			"schema_uri#integrity": "sha256-anything",
			schema: { type: "object" }
		};

		const childHash = generateSRIFromObject(conflictingMetadata);

		const payload = {
			iss: "https://issuer.com",
			vct: "https://issuer.com/child.json",
			"vct#integrity": childHash
		};

		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({
			childMetadataOverride: conflictingMetadata
		});

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		expect(result).toMatchObject({ error: "SCHEMA_CONFLICT" });
	});


	it("warning with SCHEMA_FAIL when schema validation fails", async () => {
		const invalidSchema = {
			type: "object",
			required: ["foo"], // not present in payload
			properties: {
				foo: { type: "string" }
			}
		};

		const schemaMetadata = {
			...childMetadata,
			schema: invalidSchema
		};

		const childHash = generateSRIFromObject(schemaMetadata);

		const payload = {
			iss: "https://issuer.com",
			vct: "https://issuer.com/child.json",
			"vct#integrity": childHash
			// missing required "foo"
		};

		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({
			childMetadataOverride: schemaMetadata
		});

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'SCHEMA_FAIL')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});


	it("warning with JWT_VC_ISSUER_FAIL when .well-known/jwt-vc-issuer fetch fails", async () => {
		const payload = {
			iss: "https://issuer.com",
			vct: "https://issuer.com/child.json",
			"vct#integrity": generateSRIFromObject(childMetadata)
		};

		const credential = `${encodeBase64Url({})}.${encodeBase64Url(payload)}.sig`;

		const httpClient = createHttpClient({
			childMetadataOverride: childMetadata
		});

		httpClient.get = async (url: string) => {
			if (url.endsWith("/.well-known/jwt-vc-issuer")) {
				return { status: 404, data: null };
			}
			if (url.endsWith("child.json")) {
				return { status: 200, data: childMetadata };
			}
			if (url.endsWith("parent.json")) {
				return { status: 200, data: parentMetadata };
			}
			return { status: 404, data: null };
		};

		const result = await getSdJwtVcMetadata(context, httpClient, credential, payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'JWT_VC_ISSUER_FAIL')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

});

function createHttpClient(): HttpClient {
	return {
		get: async () => {
			throw new Error("Should not be called for vctm tests");
		},
		post: async () => {
			throw new Error("POST not implemented");
		}
	};
}

const metadata1 = {
	vct: "urn:eudi:pid:1",
	display: [{ lang: "en-US", name: "PID", description: "Person ID" }],
	claims: [{ path: ["pid"], sd: "always", display: [{ lang: "en-US", label: "PID" }] }]
};

const metadata2 = {
	vct: "urn:eudi:nin:2",
	display: [{ lang: "en-US", name: "NIN", description: "National ID" }],
	claims: [{ path: ["nin"], sd: "always", display: [{ lang: "en-US", label: "NIN" }] }]
};

/**
 * Decodes a base64url-encoded string to a parsed JSON object.
 */
export function decodeBase64UrlToObject(base64url: string): unknown {
	const json = Buffer.from(base64url, "base64url").toString("utf8");
	return JSON.parse(json);
}

/**
 * Decodes an array of base64url-encoded metadata strings (for vctm).
 */
export function decodeVctmArray(encodedArray: string[]): Record<string, any>[] {
	return encodedArray.map((entry, index) => {
		try {
			return decodeBase64UrlToObject(entry) as Record<string, any>;
		} catch (e) {
			throw new Error(`VCTM_DECODE_FAIL at index ${index}: ${e instanceof Error ? e.message : String(e)}`);
		}
	});
}

/**
 * Builds a JWT string from header and payload objects.
 */
export function buildJwtLikeCredential(header: any, payload: any): string {
	return [
		encodeBase64Url(header),
		encodeBase64Url(payload),
		"sig"
	].join(".");
}

describe("getSdJwtVcTypeMetadata - failure cases (vctm)", () => {

	it("warning on vctm#integrity mismatch", async () => {
		const badIntegrity = "sha256-wronghash===";
		const payload = { vct: "urn:eudi:pid:1", iss: "https://issuer.com" };

		const header = {
			alg: "ES256",
			vctm: [encodeBase64Url(metadata1), encodeBase64Url(metadata2)],
		};


		const result = await getSdJwtVcMetadata(context, createHttpClient(), encodeBase64Url(header), payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'INTEGRITY_MISSING')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

	it("warning on vctm#integrity failed", async () => {
		const badIntegrity = "sha256-wronghash===";
		const payload = { vct: "urn:eudi:pid:1", iss: "https://issuer.com", "vct#integrity": badIntegrity };

		const header = {
			vctm: [encodeBase64Url(metadata1), encodeBase64Url(metadata2)],
		};


		const result = await getSdJwtVcMetadata(context, createHttpClient(), encodeBase64Url(header), payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'INTEGRITY_FAIL')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});


	it("succeeds with valid vctm list and matching vct#integrity", async () => {
		const metadata = {
			vct: "urn:eudi:pid:1",
			display: [{ lang: "en-US", name: "PID", description: "Person ID" }],
			claims: [{ path: ["pid"], sd: "always", display: [{ lang: "en-US", label: "PID" }] }],
			schema: {
				type: "object",
				required: ["pid"],
				properties: {
					pid: { type: "string" }
				}
			}
		};

		const encodedMetadata = encodeBase64Url(metadata);
		const integrity = generateSRIFromObject(metadata);

		const header = {
			alg: "ES256",
			vctm: [encodedMetadata],
			"vctm#integrity": [integrity]
		};

		const payload = {
			vct: "urn:eudi:pid:1",
			iss: "https://issuer.com",
			"vct#integrity": integrity,
			pid: "123456789"
		};

		const credential = buildJwtLikeCredential(header, payload);

		const result = await getSdJwtVcMetadata(context, createHttpClient(), credential, payload);
		expect(result).toMatchObject({
			credentialMetadata: {
				...metadata,
				schema: metadata.schema // schema should be injected into the final output
			}
		});


	});

	it("succeeds when child metadata in vctm extends parent metadata", async () => {
		const parentMetadata = {
			vct: "urn:eudi:parent",
			display: [{ lang: "en-US", name: "Base Person", description: "Parent Metadata" }],
			claims: [{ path: ["name"], sd: "always", display: [{ lang: "en-US", label: "Full Name" }] }]
		};

		const parentIntegrity = generateSRIFromObject(parentMetadata);

		const childMetadata = {
			vct: "urn:eudi:pid:1",
			extends: "urn:eudi:parent",
			"extends#integrity": parentIntegrity,
			display: [{ lang: "en-US", name: "PID", description: "Extended Metadata" }],
			claims: [{ path: ["pid"], sd: "always", display: [{ lang: "en-US", label: "PID" }] }]
		};

		const childIntegrity = generateSRIFromObject(childMetadata);

		const header = {
			alg: "ES256",
			vctm: [encodeBase64Url(childMetadata), encodeBase64Url(parentMetadata)],
			"vctm#integrity": [childIntegrity, parentIntegrity]
		};

		const payload = {
			vct: "urn:eudi:pid:1",
			iss: "https://issuer.com",
			"vct#integrity": childIntegrity,
			pid: "123456789",
			name: "Jane Doe" // from parent
		};

		const credential = buildJwtLikeCredential(header, payload);

		const result = await getSdJwtVcMetadata(context, createHttpClient(), credential, payload);

		expect(result).toMatchObject({
			credentialMetadata: {
				...parentMetadata,
				...childMetadata,
				claims: [...parentMetadata.claims, ...childMetadata.claims]
			}
		});
	});

	it("warning when vct is a URN and vctm is IS empty", async () => {
		const payload = {
			vct: "urn:eudi:pid:1", // not a URL
			iss: "https://issuer.com"
		};

		const header = {
			alg: "ES256",
			vctm: []
		};

		const credential = buildJwtLikeCredential(header, payload);

		const result = await getSdJwtVcMetadata(context, createHttpClient(), credential, payload);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'NOT_FOUND')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}	});

	it("warning when vct is a URN and vctm is missing", async () => {
		const payload = {
			vct: "urn:eudi:pid:1", // not a URL
			iss: "https://issuer.com"
		};

		const header = {
			alg: "ES256",
			// ⚠️ no vctm provided
		};

		const credential = buildJwtLikeCredential(header, payload);

		const result = await getSdJwtVcMetadata(context, createHttpClient(), credential, payload);

		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'NOT_FOUND')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

});
