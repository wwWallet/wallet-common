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
