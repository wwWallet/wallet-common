import { describe, it, assert } from "vitest";
import { prependToPath } from "./urlPathUtils";

describe("prependToPath", () => {
	it("should insert a path segment between the host and the existing path", async () => {
		const result = prependToPath("https://example.com/bar", "foo");
		assert(result === "https://example.com/foo/bar");
	});

	it("should handle a URL with an empty path", async () => {
		const result = prependToPath("https://example.com", "foo");
		assert(result === "https://example.com/foo");
	});

	it("should handle an empty path segment", async () => {
		const result = prependToPath("https://example.com/foo", "");
		assert(result === "https://example.com/foo");
	});

	it("should return null for an invalid URL", async () => {
		const result = prependToPath("not a url", "test");
		assert(result === null);
	});

	it("should handle multiple path segments in the segment", async () => {
		const result = prependToPath("https://example.com/issuer", ".well-known/oauth-authorization-server");
		assert(result === "https://example.com/.well-known/oauth-authorization-server/issuer");
	});

	it("should handle multiple path segments in the URL path", async () => {
		const result = prependToPath("https://example.com/idp/realms/issuer", ".well-known/openid-credential-issuer");
		assert(result === "https://example.com/.well-known/openid-credential-issuer/idp/realms/issuer");
	});

	it("should handle a trailing slash in the URL", async () => {
		const result = prependToPath("https://example.com/test/", "/.well-known/oauth-authorization-server/");
		assert(result === "https://example.com/.well-known/oauth-authorization-server/test");
	});

	it("should handle leading/trailing slashes in the segment", async () => {
		const result = prependToPath("https://example.com/test", "/.well-known/oauth-authorization-server/");
		assert(result === "https://example.com/.well-known/oauth-authorization-server/test");
	});

	it("should handle a URL with query parameters and hash fragment", async () => {
		const result = prependToPath("https://example.com/test?query=param#fragment", ".well-known/oauth-authorization-server");
		assert(result === "https://example.com/.well-known/oauth-authorization-server/test?query=param#fragment");
	});
});
