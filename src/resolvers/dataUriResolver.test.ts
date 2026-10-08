import { expect, it, vi } from "vitest";
import { CustomCredentialSvg } from "../functions/CustomCredentialSvg";
import { CredentialRenderingService } from "../rendering";
import { dataUriResolver } from "./dataUriResolver";

it("falls back when an uncached SVG template is unavailable offline", async () => {
	const httpClient = {
		get: vi.fn().mockResolvedValue({
			status: 504,
			headers: {},
			data: "No cached response available and offline",
		}),
		post: vi.fn(),
	};
	const resolveDataUri = dataUriResolver({
		httpClient,
		customRenderer: CustomCredentialSvg({ httpClient }),
		sdJwtVcRenderer: CredentialRenderingService(),
		credentialDisplayArray: [{
			locale: "en-US",
			name: "Credential",
			rendering: {
				svg_templates: [{ uri: "https://issuer.example/template.svg" }],
				simple: {},
			},
		}],
	});

	const result = await resolveDataUri();
	const svg = decodeURIComponent(result!.replace("data:image/svg+xml;utf8,", ""));

	expect(svg).toContain('fill="#D3D3D3"');
});

it("tries the next SVG template before simple rendering when the preferred one is unavailable", async () => {
	const portraitUri = "https://issuer.example/portrait.svg";
	const landscapeUri = "https://issuer.example/landscape.svg";
	const landscapeSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="320" height="200"><text>Landscape fallback</text></svg>';
	const httpClient = {
		get: vi.fn(async (uri: string) => uri === landscapeUri
			? { status: 200, headers: {}, data: landscapeSvg }
			: { status: 504, headers: {}, data: "No cached response available and offline" }),
		post: vi.fn(),
	};
	const resolveDataUri = dataUriResolver({
		httpClient,
		customRenderer: CustomCredentialSvg({ httpClient }),
		sdJwtVcRenderer: CredentialRenderingService(),
		credentialDisplayArray: [{
			locale: "en-US",
			name: "Credential",
			rendering: {
				svg_templates: [
					{ uri: landscapeUri, properties: { orientation: "landscape" } },
					{ uri: portraitUri, properties: { orientation: "portrait" } },
				],
				simple: { background_color: "#ff0000" },
			},
		}],
	});

	const result = await resolveDataUri(undefined, ["en-US"], { orientation: "portrait" });
	const svg = decodeURIComponent(result!.replace("data:image/svg+xml;utf8,", ""));

	expect(httpClient.get).toHaveBeenNthCalledWith(1, portraitUri, {}, { useCache: true });
	expect(httpClient.get).toHaveBeenNthCalledWith(2, landscapeUri, {}, { useCache: true });
	expect(svg).toContain("Landscape fallback");
	expect(svg).not.toContain('fill="#ff0000"');
});
