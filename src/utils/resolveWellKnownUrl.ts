/**
 * Insert a well-known string between the host component and the path component of a given URL, as per RFC 5785.
 * @param identifierUrl a URL identifier that may contain an existing path component
 * @param wellKnownName a well-known name to insert into the URL path after the .well-known path segment.
 * @param search whether to preserve the search parameters from the input URL in the output URL (default: false)
 * @param hash whether to preserve the hash fragment from the input URL in the output URL (default: false)
 * @returns a new URL string with the well-known name inserted, or null if the input URL is invalid or parameters are missing.
 * @example resolveWellKnownUrl("https://example.com/test", "oauth-authorization-server") => "https://example.com/.well-known/oauth-authorization-server/test"
 * @example resolveWellKnownUrl("https://example.com/", "openid-credential-issuer") => "https://example.com/.well-known/openid-credential-issuer/"
 */
export function resolveWellKnownUrl(
	identifierUrl: string,
	wellKnownName: string,
	search: boolean = false,
	hash: boolean = false,
): string | null {
	if (!identifierUrl || !wellKnownName) return null;

	let url: URL;
	try {
		url = new URL(identifierUrl);
	} catch {
		return null;
	}

	const pathSegments = url.pathname.split("/").filter(Boolean);

	const newPathSegments = [".well-known", wellKnownName, ...pathSegments];

	url.pathname = "/" + newPathSegments.join("/");

	url.search = search ? url.search : "";
	url.hash = hash ? url.hash : "";

	return url.toString();
}
