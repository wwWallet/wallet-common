import { TypeMetadata } from "../schemas/SdJwtVcTypeMetadataSchema";

export enum VctMetadataErrorCode {
	InvalidSchema = "invalid_schema",
}

export type VctMetadataResult = TypeMetadata | null | { error: VctMetadataErrorCode };

export interface VctDocumentProvider {
	getVctMetadataDocument(vct: string): Promise<unknown | null>;
}

export const createVctDocumentResolutionEngine = (providers: VctDocumentProvider[]): VctDocumentProvider => {

	return {
		getVctMetadataDocument: async (vct: string) => {
			try {
				const results = await Promise.all(providers.map((p) => p.getVctMetadataDocument(vct)));
				for (const r of results) {
					if (r === null) continue;

					const parsed = TypeMetadata.safeParse(r);
					if (parsed.success) return parsed.data;

					return { error: VctMetadataErrorCode.InvalidSchema };
				}
			}
			catch {
				return null;
			}
			return null;
		},
	};
};
