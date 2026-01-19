import { TypeMetadata } from "../schemas/SdJwtVcTypeMetadataSchema";

export interface VctDocumentProvider {
	getVctMetadataDocument(vct: string): Promise<TypeMetadata | null>;
}

export const createVctDocumentResolutionEngine = (providers: VctDocumentProvider[]): VctDocumentProvider => {

	return {
		getVctMetadataDocument: async (vct: string) => {
			try {
				const results = await Promise.all(providers.map((p) => p.getVctMetadataDocument(vct)));
				for (const r of results) {
					if (r !== null) {
						return r;
					}
				}
			}
			catch {
				return null;
			}
			return null;
		},
	}
}
