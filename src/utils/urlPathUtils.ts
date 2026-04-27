/**
 * Insert a path string between the host component and the path component of a given URL.
 * @param urlString a URL identifier that may contain an existing path component
 * @param segment a path segment to insert into the URL path.
 * @param search whether to preserve the search parameters from the input URL in the output URL (default: false)
 * @param hash whether to preserve the hash fragment from the input URL in the output URL (default: false)
 * @returns a new URL string with the path segment inserted, or null if the input URL is invalid
 * @example prependToPath("https://example.com/test", ".well-known/oauth-authorization-server") => "https://example.com/.well-known/oauth-authorization-server/test"
 * @example prependToPath("https://example.com/", ".well-known/openid-credential-issuer") => "https://example.com/.well-known/openid-credential-issuer"
 */
export function prependToPath(urlString: string, segment: string): string | null {

	if (!urlString) return null;
	if (!segment) return urlString;

	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		return null;
	}

	const pathSegments = url.pathname.split("/").filter(Boolean);

	const newSegment = segment.split("/").filter(Boolean);

	const newPathSegments = [...newSegment, ...pathSegments];
	url.pathname = "/" + newPathSegments.join("/").replace(/^\/+/, "");

	return url.toString();
}
