import { describe, it, assert } from "vitest";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { HttpClient } from "../interfaces";
import { CredentialParsingError } from "../error";
import { MetadataWarning } from "../types";

describe("getIssuerMetadata", () => {
	it("should warn if issuer metadata fetch fails", async () => {
		const warnings: MetadataWarning[] = [];

		const httpClient: HttpClient = {
			get: async (url: string) => {
				if (url.includes(".well-known/openid-credential-issuer")) {
					return { status: 400 };
				}
				throw new Error("Unexpected call");
			}
		};

		const result = await getIssuerMetadata(httpClient, "https://example.com", warnings);

		assert(result.metadata === null);
		assert(warnings.some(w => w.code === CredentialParsingError.FailFetchIssuerMetadata));
	});

	it("should warn if issuer metadata has invalid schema", async () => {
		const warnings: MetadataWarning[] = [];

		const httpClient: HttpClient = {
			get: async (url: string) => {
				if (url.includes(".well-known/openid-credential-issuer")) {
					return {
						status: 200,
						data: {
							invalid_field: true, // missing required schema fields
						}
					};
				}
				throw new Error("Unexpected call");
			}
		};

		const result = await getIssuerMetadata(httpClient, "https://example.com", warnings);
		assert(result.metadata === null);
		assert(warnings.some(w => w.code === CredentialParsingError.FailSchemaIssuerMetadata));
	});
});
