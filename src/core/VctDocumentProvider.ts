import { TypeMetadata } from "../schemas/SdJwtVcTypeMetadataSchema";
import { err, ok, Result } from "./Result";

export const VctResolutionErrors = {
	InvalidSchema: "invalid_schema",
	NotFound: "not_found",
} as const;

export type VctResolutionError = (typeof VctResolutionErrors)[keyof typeof VctResolutionErrors];


export interface VctDocumentProvider {
	getVctMetadataDocument(vct: string): Promise<Result<TypeMetadata, VctResolutionError>>;
}

export const createVctDocumentResolutionEngine = (providers: VctDocumentProvider[]): VctDocumentProvider => {

	return {
		getVctMetadataDocument: async (vct: string) => {
			try {
				const results = await Promise.all(providers.map((p) => p.getVctMetadataDocument(vct)));
				for (const r of results) {
					if (!r.ok) continue;

					const parsed = TypeMetadata.safeParse(r.value);
					if (parsed.success) return ok(parsed.data);
					const error_description = JSON.stringify(parsed.error);
					return err(VctResolutionErrors.InvalidSchema, error_description);
				}
			}
			catch {
				return err(VctResolutionErrors.NotFound);
			}
			return err(VctResolutionErrors.NotFound);
		},
	};
};
