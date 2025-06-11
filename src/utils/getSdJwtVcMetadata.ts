import { Context, HttpClient } from '../interfaces';
import { fromBase64, fromBase64Url } from './util';
import { verifySRIFromObject } from './verifySRIFromObject';
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { CredentialPayload, MetadataCode, MetadataError, MetadataWarning } from '../types';


// This can also just be Record<MetadataCode, "error" | "warning">
const CODE_SEVERITY: Record<MetadataCode, "error" | "warning"> = {
	NOT_FOUND: "warning", //optional warning
	HEADER_FAIL: "error",
	INTEGRITY_MISSING: "warning", //optional warning
	JWT_VC_ISSUER_MISMATCH: "warning", //optional warning
	SCHEMA_FETCH_FAIL: "error", //optional warning
	SCHEMA_CONFLICT: "error", //optional warning
	INFINITE_RECURSION: "error",
	PAYLOAD_FAIL: "error",
	VCTM_DECODE_FAIL: "error",
	UNKNOWN_ERROR: "error",
	INTEGRITY_FAIL: "warning", //optional warning
	SCHEMA_FAIL: "warning", //optional warning
	JWT_VC_ISSUER_FAIL: "warning" //optional warning
};

function isWarning(code: MetadataCode): boolean {
	return CODE_SEVERITY[code] === "warning";
}

function handleMetadataCode(
	code: MetadataCode,
	message: string,
	warnings: MetadataWarning[]
): MetadataError | undefined {

	if (isWarning(code)) {
		warnings.push({ code, message });
		return undefined; // continue flow
	} else {
		console.warn(`❌ Metadata Error [${code}]: ${message}`);
		return { error: code, message: message }; // now error includes message
	}
}

function deepMerge(parent: any, child: any): any {

	if (Array.isArray(parent) && Array.isArray(child)) {
		// Merge display[] by lang
		if (parent[0]?.lang && child[0]?.lang) {
			const map = new Map<string, any>();

			for (const item of parent) {
				map.set(item.lang, item);
			}
			for (const item of child) {
				if (map.has(item.lang)) {
					// Recursively merge item with same lang
					const merged = deepMerge(map.get(item.lang), item);
					map.set(item.lang, merged);
				} else {
					map.set(item.lang, item);
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

export function validateAgainstSchema(
	schema: Record<string, any>,
	dataToValidate?: Record<string, any>
): { code: MetadataCode; message: string } | undefined {

	const ajv = new Ajv2020();
	addFormats(ajv);

	// 1. Validate the schema itself
	const isSchemaValid = ajv.validateSchema(schema);
	if (!isSchemaValid) {
		console.warn('❌ Invalid schema structure:', ajv.errors);
		return { code: "SCHEMA_FAIL", message: `Invalid schema structure: ${JSON.stringify(ajv.errors)}` };
	}

	// 2. If data is provided, validate it against the schema
	if (dataToValidate) {
		try {
			const validate = ajv.compile(schema);
			const isValid = validate(dataToValidate);
			if (!isValid) {
				console.warn('❌ Data does not conform to schema:', validate.errors);
				return { code: "SCHEMA_FAIL", message: `Data does not conform to schema: ${JSON.stringify(validate.errors)}` };
			}
		} catch (err) {
			console.warn('⚠️ Error during schema compilation/validation:', err);
			return { code: "SCHEMA_FAIL", message: `Error during schema compilation/validation: ${err}` };
		}
	}

	return undefined;
}

function isObjectRecord(data: unknown): data is Record<string, any> {
	return typeof data === 'object' && data !== null && !Array.isArray(data);
}

function isInvalidSchemaResponse(res: any): res is { status: number; data: Record<string, any> } {
	return (
		!res ||
		res.status !== 200 ||
		typeof res.data !== 'object' ||
		res.data === null ||
		Array.isArray(res.data)
	);
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
): Promise<Record<string, any> | MetadataError | undefined> {

	if (visited.has(metadataId)) {
		const resultCode = handleMetadataCode("INFINITE_RECURSION", `Infinite recursion for ${metadataId}`, warnings);
		if (resultCode) return resultCode;
	}
	visited.add(metadataId);

	let metadata;

	if (metadataArray && Array.isArray(metadataArray)) {
		metadata = metadataArray.find((m) => m.vct === metadataId);

		if (!metadata) {
			return undefined;
		}

		if (!integrity) {
			const resultCode = handleMetadataCode("INTEGRITY_MISSING", `Integrity missing for ${metadataId}`, warnings);
			if (resultCode) return resultCode;
		} else {
			const isValid = await verifySRIFromObject(context, metadata, integrity);
			if (!isValid) {
				const resultCode = handleMetadataCode("INTEGRITY_FAIL", `Integrity check fail failed for ${metadataId}`, warnings);
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

		if (integrity) {
			const isValid = await verifySRIFromObject(context, result.data, integrity);
			if (!isValid) {
				const resultCode = handleMetadataCode("INTEGRITY_FAIL", `Integrity check fail failed for ${metadataId}`, warnings);
				if (resultCode) return resultCode;
			}
		}

		metadata = result.data as Record<string, any>;
	}

	if ('schema' in metadata && 'schema_uri' in metadata) {
		const resultCode = handleMetadataCode("SCHEMA_CONFLICT", `Both schema and schema_uri exists in ${metadataId}`, warnings);
		if (resultCode) return resultCode;
	}

	if ('schema' in metadata) {
		const resultValidate = validateAgainstSchema(metadata.schema, credentialPayload);
		if (resultValidate) {
			const resultCode = handleMetadataCode(resultValidate.code, resultValidate.message, warnings);
			if (resultCode) return resultCode;
		}
	}

	if (metadata.schema_uri && typeof metadata.schema_uri === 'string') {

		const resultSchema = await httpClient.get(metadata.schema_uri, {}, { useCache: true });
		if (isInvalidSchemaResponse(resultSchema)) {
			const resultCode = handleMetadataCode("SCHEMA_FETCH_FAIL", `Invalid Schema Response ${metadata.schema_uri}`, warnings);
			if (resultCode) return resultCode;
		}

		if (!isObjectRecord(resultSchema.data)) {
			const resultCode = handleMetadataCode("SCHEMA_FETCH_FAIL", `Invalid Schema Response ${metadata.schema_uri}`, warnings);
			if (resultCode) return resultCode;
		}

		const resultSchemaData = resultSchema.data as Record<string, any>;
		const schemaIntegrity = metadata['schema_uri#integrity'];

		if (schemaIntegrity) {
			if (!(await verifySRIFromObject(context, resultSchemaData, schemaIntegrity))) {
				const resultCode = handleMetadataCode("INTEGRITY_FAIL", `Integrity schema check fail failed for ${metadataId}`, warnings);
				if (resultCode) return resultCode;
			}
		}

		const resultValidate = validateAgainstSchema(resultSchemaData, credentialPayload);
		if (resultValidate) {
			const resultCode = handleMetadataCode(resultValidate.code, resultValidate.message, warnings);
			if (resultCode) return resultCode;
		}

		// Inject schema into metadata before assigning it to `current`
		metadata = {
			...metadata,
			schema: resultSchema.data,
		};
	}

	let merged: Record<string, any> = {};

	if (typeof metadata.extends === 'string') {
		const childIntegrity = metadata['extends#integrity'] as string | undefined;
		const parent = await fetchAndMergeMetadata(context, httpClient, metadata.extends, metadataArray || undefined, visited, childIntegrity, warnings);
		if (parent === undefined || 'error' in parent) return parent;
		merged = deepMerge(parent, metadata);
	} else {
		merged = metadata;
	}
	return merged;
}

export async function resolveIssuerMetadata(httpClient: any, issuerUrl: string): Promise<{ code: MetadataCode; message: string } | undefined> {
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
				return { code: 'JWT_VC_ISSUER_MISMATCH', message: `Mismatch on jwt-vc-issuer between ${result.data.issuer} and ${issUrl.origin}` };
			}
		}

		return undefined;
	} catch (err) {
		return { code: 'JWT_VC_ISSUER_FAIL', message: `Fail to fetch jwt-vc-issuer for ${issuerUrl} with err ${err}` };
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

export async function getSdJwtVcMetadata(context: Context, httpClient: HttpClient, credential: string, parsedClaims: Record<string, unknown>): Promise<{ credentialMetadata: any; warnings: MetadataWarning[] } | MetadataError> {
	try {

		const warnings: MetadataWarning[] = [];

		// Decode Header
		let credentialHeader: any;
		try {
			credentialHeader = JSON.parse(new TextDecoder().decode(fromBase64Url(credential.split('.')[0] as string)));
		} catch (e) {
			console.warn('Failed to decode credential header:', e);
			const resultCode = handleMetadataCode("HEADER_FAIL", "Failed to decode credential header", warnings);
			if (resultCode) return resultCode;
		}

		if (!credentialHeader || typeof credentialHeader !== 'object') {
			console.warn('Invalid or missing credential header structure.');
			return { error: "HEADER_FAIL", message: "Invalid or missing credential header structure." };
		}
		const credentialPayload = parsedClaims;

		if (!credentialPayload || !isCredentialPayload(credentialPayload)) {
			return { error: "PAYLOAD_FAIL", message: "Invalid or missing credential payload structure." };
		}
		const vct = credentialPayload.vct;
		if (vct && typeof vct === 'string' && isValidHttpUrl(vct)) {

			// Check jwt-vc-issuer by iss 
			const checkIssuer = await resolveIssuerMetadata(httpClient, credentialPayload.iss);
			if (checkIssuer) {
				const resultCode = handleMetadataCode(checkIssuer.code, checkIssuer.message, warnings);
				if (resultCode) return resultCode;
			}

			try {
				const vctIntegrity = credentialPayload['vct#integrity'] as string | undefined;
				const mergedMetadata = await fetchAndMergeMetadata(context, httpClient, vct, undefined, new Set(), vctIntegrity, credentialPayload, warnings);
				if (mergedMetadata) {
					if ('error' in mergedMetadata) {
						return { error: mergedMetadata.error, message: mergedMetadata.message }
					} else {
						return { credentialMetadata: mergedMetadata, warnings };
					}
				}
			} catch (e) {
				console.warn('Invalid vct URL:', vct, e);
			}
		}

		if (credentialHeader.vctm && Array.isArray(credentialHeader.vctm)) {
			const decodedVctmList = credentialHeader.vctm.map((encoded: string, index: number) => {
				try {
					return JSON.parse(new TextDecoder().decode(fromBase64Url(encoded)));
				} catch (err) {
					return { error: "VCTM_DECODE_FAIL", message: "vctm decode fail" }
				}
			});

			const vctIntegrity = credentialPayload['vct#integrity'] as string | undefined;
			const vctmMergedMetadata = await fetchAndMergeMetadata(context, httpClient, credentialPayload.vct, decodedVctmList, new Set(), vctIntegrity, credentialPayload, warnings);

			if (vctmMergedMetadata) {
				if ('error' in vctmMergedMetadata) {
					return { error: vctmMergedMetadata.error, message: vctmMergedMetadata.message }
				} else {
					console.log('Final vctm Metadata:', vctmMergedMetadata);
					return { credentialMetadata: vctmMergedMetadata, warnings };
				}
			}
		}

		// if no metafata found return NOT_FOUND
		// here you add more ways to find metadata (eg registry)
		warnings.push({ code: "NOT_FOUND", message: "Not found any type metadata" });

		return { credentialMetadata: undefined, warnings };
	}
	catch (err) {
		console.log(err);
		return { error: "UNKNOWN_ERROR", message: `${err}` };
	}
}
