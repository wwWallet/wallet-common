import { HttpClient } from '../interfaces';
import { verifySRIFromObject } from './verifySRIFromObject';
import { MetadataError, MetadataWarning } from '../types';
import { CredentialParsingError, isCredentialParsingWarnings } from '../error';
import { TypeMetadata as TypeMetadataSchema } from "../schemas/SdJwtVcTypeMetadataSchema";
import { VctDocumentProvider } from '../core';

function validateTypeMetadataShape(
	metadata: unknown,
): { ok: true; data: TypeMetadataSchema } | { ok: false; code: CredentialParsingError } {
	const res = TypeMetadataSchema.safeParse(metadata);
	if (!res.success) {
		console.error("❌ Type Metadata shape validation failed:", res.error.issues);
		return { ok: false, code: CredentialParsingError.SchemaShapeFail };
	}
	return { ok: true, data: res.data };
}

function handleMetadataCode(
	code: CredentialParsingError,
	warnings: MetadataWarning[]
): MetadataError | undefined {

	if (isCredentialParsingWarnings(code)) {
		warnings.push({ code });
		return undefined; // continue flow
	} else {
		console.warn(`❌ Metadata Error [${code}]`);
		return { error: code }; // now error
	}
}

function deepMerge(parent: any, child: any): any {

	if (Array.isArray(parent) && Array.isArray(child)) {
		// Merge display[] by locale
		if (parent[0]?.locale && child[0]?.locale) {
			const map = new Map<string, any>();

			for (const item of parent) {
				map.set(item.locale, item);
			}
			for (const item of child) {
				if (map.has(item.locale)) {
					// Recursively merge item with same locale
					const merged = deepMerge(map.get(item.locale), item);
					map.set(item.locale, merged);
				} else {
					map.set(item.locale, item);
				}
			}
			return Array.from(map.values());
		}

		// Merge claims[] by path
		if (parent[0]?.path && child[0]?.path) {
			const map = new Map<string, any>();

			for (const item of parent) {
				map.set(JSON.stringify(item.path), item);
			}
			for (const item of child) {
				if (map.has(JSON.stringify(item.path))) {
					const merged = deepMerge(map.get(JSON.stringify(item.path)), item);
					map.set(JSON.stringify(item.path), merged);
				} else {
					map.set(JSON.stringify(item.path), item);
				}
			}
			return Array.from(map.values());
		}

		// If they're not arrays of objects (i.e., primitives), override with child
		if (
			typeof parent[0] !== 'object' ||
			typeof child[0] !== 'object' ||
			parent[0] === null ||
			child[0] === null
		) {
			return child;
		}

		// Otherwise, merge arrays of objects (default behavior)
		return [...parent, ...child];

	}

	if (typeof parent === 'object' && typeof child === 'object' && parent !== null && child !== null) {
		const result: Record<string, any> = { ...parent };
		for (const key of Object.keys(child)) {
			if (key in parent) {
				result[key] = deepMerge(parent[key], child[key]); // RECURSIVE
			} else {
				result[key] = child[key];
			}
		}
		return result;
	}

	// Primitives: child overrides
	return child;
}

async function fetchAndMergeMetadata(
	vctResolutionEngine: VctDocumentProvider | undefined,
	subtle: SubtleCrypto,
	httpClient: HttpClient,
	metadataId: string,
	visited = new Set<string>(),
	integrity?: string,
	warnings: MetadataWarning[] = []
): Promise<TypeMetadataSchema | MetadataError | undefined> {

	if (visited.has(metadataId)) {
		const resultCode = handleMetadataCode(CredentialParsingError.InfiniteRecursion, warnings);
		if (resultCode) return resultCode;
	}
	visited.add(metadataId);

	let metadata: TypeMetadataSchema | undefined;

	// HTTP (only if valid URL)
	if (isValidHttpUrl(metadataId)) {
		const res = await httpClient.get(metadataId, {}, { useCache: true });

		if (
			res &&
			res.status === 200 &&
			typeof res.data === 'object' &&
			res.data !== null &&
			'vct' in (res.data as any)
		) {
			const validated = validateTypeMetadataShape(res.data);

			if (!validated.ok) {
				const resultCode = handleMetadataCode(validated.code, warnings);
				if (resultCode) return resultCode;

			} else {
				metadata = validated.data as TypeMetadataSchema;
			}
		}
	}

	// Registry
	if (!metadata && vctResolutionEngine) {
		const maybe = await vctResolutionEngine.getVctMetadataDocument(metadataId);
		if (maybe?.ok) {
			metadata = maybe.value as TypeMetadataSchema;
		} else if (maybe?.error === "invalid_schema") {
			const resultCode = handleMetadataCode(CredentialParsingError.SchemaShapeFail, warnings);
			if (resultCode) return resultCode;
		}
	}

	if (!metadata) return undefined;

	if (integrity) {
		const isValid = await verifySRIFromObject(subtle, metadata, integrity);
		if (!isValid) {
			const resultCode = handleMetadataCode(CredentialParsingError.IntegrityFail, warnings);
			if (resultCode) return resultCode;
		}
	}

	let merged;

	if (typeof metadata.extends === 'string') {
		const childIntegrity = metadata['extends#integrity'] as string | undefined;
		const parent = await fetchAndMergeMetadata(vctResolutionEngine, subtle, httpClient, metadata.extends, visited, childIntegrity, warnings);
		if (parent === undefined) {
			const resultCode = handleMetadataCode(CredentialParsingError.NotFoundExtends, warnings);
			if (resultCode) return resultCode;
			return metadata;
		}
		if ('error' in parent) return parent;
		merged = deepMerge(parent, metadata);
	} else {
		merged = metadata;
	}
	return merged;
}

export async function resolveIssuerMetadata(httpClient: any, issuerUrl: string): Promise<{ code: CredentialParsingError } | undefined> {
	try {
		const issUrl = new URL(issuerUrl);

		const result = await httpClient.get(`${issUrl.origin}/.well-known/jwt-vc-issuer`, {}, { useCache: true }) as {
			data: { issuer: string };
		};

		if (
			result &&
			typeof result === 'object' &&
			('data' in result) &&
			typeof (result as any).data === 'object' &&
			typeof (result as any).data.issuer === 'string'
		) {
			if (result.data.issuer !== issUrl.origin) {
				return { code: CredentialParsingError.JwtVcIssuerMismatch };
			}
		}

		return undefined;
	} catch (err) {
		return { code: CredentialParsingError.JwtVcIssuerFail };
	}
}

function isValidHttpUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol.startsWith('http');
	} catch {
		return false;
	}
}

export async function getSdJwtVcMetadata(vctResolutionEngine: VctDocumentProvider | undefined, subtle : SubtleCrypto, httpClient: HttpClient, vct: string, vctIntegrity: string | undefined, warnings: MetadataWarning[] = []): Promise<{ credentialMetadata: TypeMetadataSchema | undefined; warnings: MetadataWarning[] } | MetadataError> {
	try {
		if (vct && typeof vct === 'string') {

			// TODO: Move to SDJWTVCVerifier
			// Check jwt-vc-issuer by iss
			// if (isValidHttpUrl(vct)) {
			// 	const checkIssuer = await resolveIssuerMetadata(httpClient, credentialPayload.iss);
			// 	if (checkIssuer) {
			// 		const resultCode = handleMetadataCode(checkIssuer.code, warnings);
			// 		if (resultCode) return resultCode;
			// 	}
			// }

			try {
				const mergedMetadata = await fetchAndMergeMetadata(vctResolutionEngine, subtle, httpClient, vct, new Set(), vctIntegrity, warnings);
				if (mergedMetadata) {
					if ('error' in mergedMetadata) {
						return { error: mergedMetadata.error }
					} else {
						return { credentialMetadata: mergedMetadata, warnings };
					}
				}
			} catch (e) {
				console.warn('Invalid vct URL:', vct, e);
			}
		}

		// if no metafata found return NotFound
		warnings.push({ code: CredentialParsingError.NotFound });

		return { credentialMetadata: undefined, warnings };
	}
	catch (err) {
		console.log(err);
		return { error: CredentialParsingError.UnknownError };
	}
}
