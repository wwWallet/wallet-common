import type { HttpClient } from "../interfaces";

export async function loadSvgTemplate(
	uri: string,
	httpClient: HttpClient
): Promise<string | null> {
	if (uri.startsWith('data:')) {
		const blob = await fetch(uri)
			.then((response) => response.blob())
			.catch(() => null);

		if (!blob) return null;
		if (blob.type !== 'image/svg+xml') {
			console.warn(`Unsupported SVG template data URI type: ${blob.type}`);
			return null;
		}

		return blob.text().catch(() => null);
	}

	if (uri.startsWith('http')) {
		const response = await httpClient
			.get(uri, {}, { useCache: true })
			.catch(() => null);

		if (
			response &&
			response.status >= 200 &&
			response.status < 300 &&
			typeof response.data === 'string'
		) {
			return response.data;
		}
	}

	return null;
}
