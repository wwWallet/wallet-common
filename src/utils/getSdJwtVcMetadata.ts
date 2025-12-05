import { Context, HttpClient } from '../interfaces';
import { fromBase64Url } from './util';
import { verifySRIFromObject } from './verifySRIFromObject';
import { CredentialPayload, MetadataError, MetadataWarning } from '../types';
import { CredentialParsingError, isCredentialParsingWarnings } from '../error';
import { TypeMetadata as TypeMetadataSchema } from "../schemas/SdJwtVcTypeMetadataSchema";

function validateTypeMetadataShape(
	metadata: Record<string, any>,
): CredentialParsingError | undefined {
	const res = TypeMetadataSchema.safeParse(metadata);
	if (!res.success) {
		console.error("❌ Type Metadata shape validation failed:", res.error.issues);
		return CredentialParsingError.SchemaShapeFail;
	}
	return undefined;
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
	context: Context,
	httpClient: HttpClient,
	metadataId: string,
	metadataArray?: Object,
	visited = new Set<string>(),
	integrity?: string,
	credentialPayload?: Record<string, any>,
	warnings: MetadataWarning[] = []
): Promise<TypeMetadataSchema | MetadataError | undefined> {

	if (visited.has(metadataId)) {
		const resultCode = handleMetadataCode(CredentialParsingError.InfiniteRecursion, warnings);
		if (resultCode) return resultCode;
	}
	visited.add(metadataId);

	let metadata;

	if (metadataArray && Array.isArray(metadataArray)) {
		metadata = metadataArray.find((m) => m.vct === metadataId);

		if (!metadata) {
			return undefined;
		}

		const resultShapeCheckCode = validateTypeMetadataShape(metadata);
		if (resultShapeCheckCode) {
			const resultCode = handleMetadataCode(resultShapeCheckCode, warnings);
			if (resultCode) return resultCode;
		}

		if (!integrity) {
			const resultCode = handleMetadataCode(CredentialParsingError.IntegrityMissing, warnings);
			if (resultCode) return resultCode;
		} else {
			const isValid = await verifySRIFromObject(context, metadata, integrity);
			if (!isValid) {
				const resultCode = handleMetadataCode(CredentialParsingError.IntegrityFail, warnings);
				if (resultCode) return resultCode;
			}
		}

	}
	else {
		const result = await httpClient.get(metadataId, {}, { useCache: true });

		if (
			!result ||
			result.status !== 200 ||
			typeof result.data !== 'object' ||
			result.data === null ||
			!('vct' in result.data)
		) {
			return undefined;
		}

		const resultShapeCheckCode = validateTypeMetadataShape(result.data);
		if (resultShapeCheckCode) {
			const resultCode = handleMetadataCode(resultShapeCheckCode, warnings);
			if (resultCode) return resultCode;
		}

		if (integrity) {
			const isValid = await verifySRIFromObject(context, result.data, integrity);
			if (!isValid) {
				const resultCode = handleMetadataCode(CredentialParsingError.IntegrityFail, warnings);
				if (resultCode) return resultCode;
			}
		}

		metadata = result.data;
	}

	let merged;

	if (typeof metadata.extends === 'string') {
		const childIntegrity = metadata['extends#integrity'] as string | undefined;
		const parent = await fetchAndMergeMetadata(context, httpClient, metadata.extends, metadataArray || undefined, visited, childIntegrity, warnings);
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

function isCredentialPayload(obj: unknown): obj is CredentialPayload {
	return typeof obj === 'object' && obj !== null && 'iss' in obj && typeof (obj as any).iss === 'string';
}

export async function getSdJwtVcMetadata(context: Context, httpClient: HttpClient, credential: string, parsedClaims: Record<string, unknown>, warnings: MetadataWarning[] = []): Promise<{ credentialMetadata: TypeMetadataSchema | undefined; warnings: MetadataWarning[] } | MetadataError> {
	try {

		// Decode Header
		let credentialHeader: any;
		try {
			credentialHeader = JSON.parse(new TextDecoder().decode(fromBase64Url(credential.split('.')[0] as string)));
		} catch (e) {
			console.warn('Failed to decode credential header:', e);
			const resultCode = handleMetadataCode(CredentialParsingError.HeaderFail, warnings);
			if (resultCode) return resultCode;
		}

		if (!credentialHeader || typeof credentialHeader !== 'object') {
			console.warn('Invalid or missing credential header structure.');
			return { error: CredentialParsingError.HeaderFail };
		}
		const credentialPayload = parsedClaims;

		if (!credentialPayload || !isCredentialPayload(credentialPayload)) {
			return { error: CredentialParsingError.PayloadFail };
		}
		const vct = credentialPayload.vct;
		if (vct && typeof vct === 'string' && isValidHttpUrl(vct)) {

			// Check jwt-vc-issuer by iss
			const checkIssuer = await resolveIssuerMetadata(httpClient, credentialPayload.iss);
			if (checkIssuer) {
				const resultCode = handleMetadataCode(checkIssuer.code, warnings);
				if (resultCode) return resultCode;
			}

			try {
				const vctIntegrity = credentialPayload['vct#integrity'] as string | undefined;
				const mergedMetadata = await fetchAndMergeMetadata(context, httpClient, vct, undefined, new Set(), vctIntegrity, credentialPayload, warnings);
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

		// ─────────────────────────────────────────────
		// Fallback: vct registry (if configured)
		// ─────────────────────────────────────────────
		if (context.config?.vctRegistryUri && typeof vct === 'string') {
			try {
				const registryResult = await httpClient.get(
					context.config.vctRegistryUri,
					{},
					{ useCache: true }
				) as { status: number; data: TypeMetadataSchema[] };

				// If request fails or data is not an array, just continue
				if (
					!registryResult ||
					registryResult.status !== 200 ||
					!Array.isArray(registryResult.data)
				) {
					// nothing from registry, fall through to NotFound warning
				} else {
					const vctIntegrity = credentialPayload['vct#integrity'] as string | undefined;

					const registryMerged = await fetchAndMergeMetadata(context, httpClient, vct, registryResult.data, new Set(), vctIntegrity, credentialPayload, warnings);

					if (registryMerged) {
						if ('error' in registryMerged) {
							return { error: registryMerged.error };
						}
						return { credentialMetadata: registryMerged, warnings };
					}
				}
			} catch (err) {
				console.log('Failed to fetch metadata from vct registry:', err);
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
