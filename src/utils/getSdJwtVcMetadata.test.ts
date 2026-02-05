import { describe, it, expect } from "vitest";
import { getSdJwtVcMetadata } from "./getSdJwtVcMetadata";
import { Context, HttpClient } from "../interfaces";


import crypto from "crypto";

export function generateSRIFromObject(obj: Record<string, any>, algorithm: "sha256" | "sha384" | "sha512" = "sha256"): string {
	const jsonString = JSON.stringify(obj);
	const hash = crypto.createHash(algorithm).update(jsonString, "utf8").digest("base64");
	return `${algorithm}-${hash}`;
}

const encodeBase64Url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

const context: Context = {
	clockTolerance: 0,
	locale: "en-US",
	subtle: crypto.subtle,
	trustedCertificates: []
};

const parentMetadata = {
	vct: "https://issuer.com/parent.json",
	display: [{ locale: "en-US", name: "Parent Credential", description: "This is the parent metadata." }],
	claims: [{ path: ["parent_id"], sd: "always", display: [{ locale: "en-US", label: "Parent ID" }] }]
};

const parentIntegrity = generateSRIFromObject(parentMetadata);

const childMetadata = {
	vct: "https://issuer.com/child.json",
	extends: "https://issuer.com/parent.json",
	"extends#integrity": parentIntegrity,
	display: [{ locale: "en-US", name: "Child Credential", description: "This is the child metadata." }],
	claims: [{ path: ["child_id"], sd: "always", display: [{ locale: "en-US", label: "Child ID" }] }]
};

const childIntegrity = "sha256-ilSsfKQ7sIAV8o2aXWOxzotWG6mJNK8TwemSpdFB57k=";
const childVct = "https://issuer.com/child.json";

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

	it("warning when fetching main vct fails", async () => {

		const httpClient = createHttpClient({ failChild: true });

		const result = await getSdJwtVcMetadata(context, httpClient, childVct, childIntegrity);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'NotFound')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

	it("warning when fetching parent metadata (extends) not found", async () => {

		const httpClient = createHttpClient({
			childMetadataOverride: {
				...childMetadata,
				extends: "https://issuer.com/parent.json",
				"extends#integrity": parentIntegrity
			},
			failParent: true
		});

		const result = await getSdJwtVcMetadata(context, httpClient, childVct, childIntegrity);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'NotFoundExtends')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

	it("fails with InfiniteRecursion when metadata extends each other", async () => {
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
		const httpClient = createHttpClient({
			childMetadataOverride: circularChild,
			parentMetadataOverride: circularParent,
		});

		const result = await getSdJwtVcMetadata(context, httpClient, "https://issuer.com/child.json", circularChildIntegrity);
		expect(result).toMatchObject({ error: "InfiniteRecursion" });
	});


	it("warning on incorrect vct#integrity", async () => {
		const badIntegrity = "sha256-invalidhash===";

		const httpClient = createHttpClient({
			childMetadataOverride: childMetadata
		});

		const result = await getSdJwtVcMetadata(context, httpClient, "https://issuer.com/child.json",badIntegrity);
		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'IntegrityFail')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

});

function createHttpClient(): HttpClient {
	return {
		get: async () => {
			throw new Error("Should not be called for vct url or registry tests");
		},
		post: async () => {
			throw new Error("POST not implemented");
		}
	};
}

const metadata1 = {
	vct: "urn:eudi:pid:1",
	display: [{ locale: "en-US", name: "PID", description: "Person ID" }],
	claims: [{ path: ["pid"], sd: "always", display: [{ locale: "en-US", label: "PID" }] }]
};

const metadata2 = {
	vct: "urn:eudi:nin:2",
	display: [{ locale: "en-US", name: "NIN", description: "National ID" }],
	claims: [{ path: ["nin"], sd: "always", display: [{ locale: "en-US", label: "NIN" }] }]
};

/**
 * Decodes a base64url-encoded string to a parsed JSON object.
 */
export function decodeBase64UrlToObject(base64url: string): unknown {
	const json = Buffer.from(base64url, "base64url").toString("utf8");
	return JSON.parse(json);
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

describe("getSdJwtVcTypeMetadata - failure cases", () => {

	it("warning when vct is a URN and registry is missing", async () => {

		const result = await getSdJwtVcMetadata(context, createHttpClient(), "urn:eudi:pid:1",undefined);

		if ('warnings' in result) {
			expect(result.warnings.some(w => w.code === 'NotFound')).toBe(true);

		} else {
			throw new Error(`Expected result to be success with warnings`);
		}
	});

	describe("getSdJwtVcMetadata - rendering.simple validation", () => {
		function httpWithSimpleRendering(child: any): HttpClient {
			return {
				get: async (url: string) => {
					if (url.endsWith("child.json")) {
						return { status: 200, data: child, headers: {} };
					}
					return { status: 404, data: null, headers: {} };
				},
				post: async () => { throw new Error("POST not implemented"); }
			};
		}

		it("preserves simple rendering (logo, background_image, colors)", async () => {
			const childWithSimple = {
				vct: "https://issuer.com/child.json",
				display: [{
					locale: "en-US",
					name: "Child with Simple Rendering",
					description: "desc",
					rendering: {
						simple: {
							logo: { uri: "https://issuer.com/logo.svg" },
							background_image: { uri: "https://issuer.com/bg.svg" },
							background_color: "#112233",
							text_color: "#ffffff"
						}
					}
				}],
				claims: [{ path: ["id"], sd: "always", display: [{ locale: "en-US", label: "ID" }] }]
			};

			const result = await getSdJwtVcMetadata(context, httpWithSimpleRendering(childWithSimple), "https://issuer.com/child.json",undefined);

			if ("error" in result) throw new Error(`Unexpected error: ${result.error}`);
			expect(result.credentialMetadata?.display?.[0]?.rendering?.simple?.logo?.uri)
				.toBe("https://issuer.com/logo.svg");
			expect(result.credentialMetadata?.display?.[0]?.rendering?.simple?.background_image?.uri)
				.toBe("https://issuer.com/bg.svg");
			expect(result.credentialMetadata?.display?.[0]?.rendering?.simple?.background_color)
				.toBe("#112233");
			expect(result.credentialMetadata?.display?.[0]?.rendering?.simple?.text_color)
				.toBe("#ffffff");
		});
	});

	describe("getSdJwtVcMetadata - rendering.svg_templates validation", () => {
		function http(child: any): HttpClient {
			return {
				get: async (url: string) => {
					if (url.endsWith("child.json")) {
						return { status: 200, data: child, headers: {} };
					}
					return { status: 404, data: null, headers: {} };
				},
				post: async () => { throw new Error("POST not implemented"); }
			};
		}

		it("fails when >1 svg_templates and a template lacks properties", async () => {
			const bad = {
				vct: "https://issuer.com/child.json",
				display: [{
					locale: "en-US",
					name: "Bad SVG Templates",
					rendering: {
						svg_templates: [
							{ uri: "https://issuer.com/t1.svg", properties: { orientation: "portrait" } },
							{ uri: "https://issuer.com/t2.svg" } // ❌ missing properties
						]
					}
				}],
				claims: [{ path: ["id"], sd: "always", display: [{ locale: "en-US", label: "ID" }] }]
			};

			const result = await getSdJwtVcMetadata(context, http(bad), "https://issuer.com/child.json",undefined);
			expect(result).toMatchObject({ error: "SchemaShapeFail" }); // schema rejects it
		});

		it("succeeds when >1 svg_templates and all have properties", async () => {
			const ok = {
				vct: "https://issuer.com/child.json",
				display: [{
					locale: "en-US",
					name: "Good SVG Templates",
					rendering: {
						svg_templates: [
							{ uri: "https://issuer.com/t1.svg", properties: { orientation: "portrait" } },
							{ uri: "https://issuer.com/t2.svg", properties: { orientation: "landscape", contrast: "high" } }
						]
					}
				}],
				claims: [{ path: ["id"], sd: "always", display: [{ locale: "en-US", label: "ID" }] }]
			};

			const result = await getSdJwtVcMetadata(context, http(ok), "https://issuer.com/child.json",undefined);
			if ("error" in result) throw new Error(`Unexpected error: ${result.error}`);
			expect(result.credentialMetadata?.display?.[0]?.rendering?.svg_templates?.length).toBe(2);
		});
	});

});
