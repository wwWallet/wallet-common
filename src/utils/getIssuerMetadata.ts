import { z } from "zod";
import { OpenidCredentialIssuerMetadataSchema } from "../schemas";
import type { HttpClient } from "../interfaces";
import { MetadataWarning } from "../types";
import { CredentialParsingError } from "../error";
import { prependToPath } from "./urlPathUtils";

export async function getIssuerMetadata(
	httpClient: HttpClient,
	issuer: string,
	warnings: MetadataWarning[],
	useCache: boolean = true
): Promise<{
	metadata: z.infer<typeof OpenidCredentialIssuerMetadataSchema> | null;
}> {
	if (!issuer) return { metadata: null };

	const url = prependToPath(issuer, ".well-known/openid-credential-issuer");
	if (!url) return { metadata: null };

	let issuerResponse = null;
	try {
		issuerResponse = await httpClient.get(url, {"Accept": "application/json"}, { useCache });
	} catch (err) {
		warnings.push({
			code: CredentialParsingError.FailFetchIssuerMetadata,
		});
		return { metadata: null };
	}

	if (!issuerResponse || issuerResponse.status !== 200 || !issuerResponse.data) {
		warnings.push({
			code: CredentialParsingError.FailFetchIssuerMetadata,
		});
		return { metadata: null };
	}

	const parsed = OpenidCredentialIssuerMetadataSchema.safeParse(issuerResponse.data);
	if (!parsed.success) {
		warnings.push({
			code: CredentialParsingError.FailSchemaIssuerMetadata,
		});
		return { metadata: null };
	}

	return { metadata: parsed.data };
}
