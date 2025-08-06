"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateAgainstSchema = validateAgainstSchema;
exports.resolveIssuerMetadata = resolveIssuerMetadata;
exports.getSdJwtVcMetadata = getSdJwtVcMetadata;
const util_1 = require("./util");
const verifySRIFromObject_1 = require("./verifySRIFromObject");
const _2020_1 = __importDefault(require("ajv/dist/2020"));
const ajv_formats_1 = __importDefault(require("ajv-formats"));
const error_1 = require("../error");
function handleMetadataCode(code, warnings) {
    if ((0, error_1.isCredentialParsingWarnings)(code)) {
        warnings.push({ code });
        return undefined; // continue flow
    }
    else {
        console.warn(`❌ Metadata Error [${code}]`);
        return { error: code }; // now error
    }
}
function deepMerge(parent, child) {
    if (Array.isArray(parent) && Array.isArray(child)) {
        // Merge display[] by lang
        if (parent[0]?.lang && child[0]?.lang) {
            const map = new Map();
            for (const item of parent) {
                map.set(item.lang, item);
            }
            for (const item of child) {
                if (map.has(item.lang)) {
                    // Recursively merge item with same lang
                    const merged = deepMerge(map.get(item.lang), item);
                    map.set(item.lang, merged);
                }
                else {
                    map.set(item.lang, item);
                }
            }
            return Array.from(map.values());
        }
        // Merge claims[] by path
        if (parent[0]?.path && child[0]?.path) {
            const map = new Map();
            for (const item of parent) {
                map.set(JSON.stringify(item.path), item);
            }
            for (const item of child) {
                if (map.has(JSON.stringify(item.path))) {
                    const merged = deepMerge(map.get(JSON.stringify(item.path)), item);
                    map.set(JSON.stringify(item.path), merged);
                }
                else {
                    map.set(JSON.stringify(item.path), item);
                }
            }
            return Array.from(map.values());
        }
        // If they're not arrays of objects (i.e., primitives), override with child
        if (typeof parent[0] !== 'object' ||
            typeof child[0] !== 'object' ||
            parent[0] === null ||
            child[0] === null) {
            return child;
        }
        // Otherwise, merge arrays of objects (default behavior)
        return [...parent, ...child];
    }
    if (typeof parent === 'object' && typeof child === 'object' && parent !== null && child !== null) {
        const result = { ...parent };
        for (const key of Object.keys(child)) {
            if (key in parent) {
                result[key] = deepMerge(parent[key], child[key]); // RECURSIVE
            }
            else {
                result[key] = child[key];
            }
        }
        return result;
    }
    // Primitives: child overrides
    return child;
}
function validateAgainstSchema(schema, dataToValidate) {
    const ajv = new _2020_1.default();
    (0, ajv_formats_1.default)(ajv);
    // 1. Validate the schema itself
    const isSchemaValid = ajv.validateSchema(schema);
    if (!isSchemaValid) {
        console.warn('❌ Invalid schema structure:', ajv.errors);
        return error_1.CredentialParsingError.SchemaFail;
    }
    // 2. If data is provided, validate it against the schema
    if (dataToValidate) {
        try {
            const validate = ajv.compile(schema);
            const isValid = validate(dataToValidate);
            if (!isValid) {
                console.warn('❌ Data does not conform to schema:', validate.errors);
                return error_1.CredentialParsingError.SchemaFail;
            }
        }
        catch (err) {
            console.warn('⚠️ Error during schema compilation/validation:', err);
            return error_1.CredentialParsingError.SchemaFail;
        }
    }
    return undefined;
}
function isObjectRecord(data) {
    return typeof data === 'object' && data !== null && !Array.isArray(data);
}
function isInvalidSchemaResponse(res) {
    return (!res ||
        res.status !== 200 ||
        typeof res.data !== 'object' ||
        res.data === null ||
        Array.isArray(res.data));
}
async function fetchAndMergeMetadata(context, httpClient, metadataId, metadataArray, visited = new Set(), integrity, credentialPayload, warnings = []) {
    if (visited.has(metadataId)) {
        const resultCode = handleMetadataCode(error_1.CredentialParsingError.InfiniteRecursion, warnings);
        if (resultCode)
            return resultCode;
    }
    visited.add(metadataId);
    let metadata;
    if (metadataArray && Array.isArray(metadataArray)) {
        metadata = metadataArray.find((m) => m.vct === metadataId);
        if (!metadata) {
            return undefined;
        }
        if (!integrity) {
            const resultCode = handleMetadataCode(error_1.CredentialParsingError.IntegrityMissing, warnings);
            if (resultCode)
                return resultCode;
        }
        else {
            const isValid = await (0, verifySRIFromObject_1.verifySRIFromObject)(context, metadata, integrity);
            if (!isValid) {
                const resultCode = handleMetadataCode(error_1.CredentialParsingError.IntegrityFail, warnings);
                if (resultCode)
                    return resultCode;
            }
        }
    }
    else {
        const result = await httpClient.get(metadataId, {}, { useCache: true });
        if (!result ||
            result.status !== 200 ||
            typeof result.data !== 'object' ||
            result.data === null ||
            !('vct' in result.data)) {
            return undefined;
        }
        if (integrity) {
            const isValid = await (0, verifySRIFromObject_1.verifySRIFromObject)(context, result.data, integrity);
            if (!isValid) {
                const resultCode = handleMetadataCode(error_1.CredentialParsingError.IntegrityFail, warnings);
                if (resultCode)
                    return resultCode;
            }
        }
        metadata = result.data;
    }
    if ('schema' in metadata && 'schema_uri' in metadata) {
        const resultCode = handleMetadataCode(error_1.CredentialParsingError.SchemaConflict, warnings);
        if (resultCode)
            return resultCode;
    }
    if ('schema' in metadata) {
        const resultValidateCode = validateAgainstSchema(metadata.schema, credentialPayload);
        if (resultValidateCode) {
            const resultCode = handleMetadataCode(resultValidateCode, warnings);
            if (resultCode)
                return resultCode;
        }
    }
    if (metadata.schema_uri && typeof metadata.schema_uri === 'string') {
        const resultSchema = await httpClient.get(metadata.schema_uri, {}, { useCache: true });
        if (isInvalidSchemaResponse(resultSchema)) {
            const resultCode = handleMetadataCode(error_1.CredentialParsingError.SchemaFetchFail, warnings);
            if (resultCode)
                return resultCode;
        }
        if (!isObjectRecord(resultSchema.data)) {
            const resultCode = handleMetadataCode(error_1.CredentialParsingError.SchemaFetchFail, warnings);
            if (resultCode)
                return resultCode;
        }
        const resultSchemaData = resultSchema.data;
        const schemaIntegrity = metadata['schema_uri#integrity'];
        if (schemaIntegrity) {
            if (!(await (0, verifySRIFromObject_1.verifySRIFromObject)(context, resultSchemaData, schemaIntegrity))) {
                const resultCode = handleMetadataCode(error_1.CredentialParsingError.IntegrityFail, warnings);
                if (resultCode)
                    return resultCode;
            }
        }
        const resultValidateCode = validateAgainstSchema(resultSchemaData, credentialPayload);
        if (resultValidateCode) {
            const resultCode = handleMetadataCode(resultValidateCode, warnings);
            if (resultCode)
                return resultCode;
        }
        // Inject schema into metadata before assigning it to `current`
        metadata = {
            ...metadata,
            schema: resultSchema.data,
        };
    }
    let merged = {};
    if (typeof metadata.extends === 'string') {
        const childIntegrity = metadata['extends#integrity'];
        const parent = await fetchAndMergeMetadata(context, httpClient, metadata.extends, metadataArray || undefined, visited, childIntegrity, warnings);
        if (parent === undefined || 'error' in parent)
            return parent;
        merged = deepMerge(parent, metadata);
    }
    else {
        merged = metadata;
    }
    return merged;
}
async function resolveIssuerMetadata(httpClient, issuerUrl) {
    try {
        const issUrl = new URL(issuerUrl);
        const result = await httpClient.get(`${issUrl.origin}/.well-known/jwt-vc-issuer`, {}, { useCache: true });
        if (result &&
            typeof result === 'object' &&
            ('data' in result) &&
            typeof result.data === 'object' &&
            typeof result.data.issuer === 'string') {
            if (result.data.issuer !== issUrl.origin) {
                return { code: error_1.CredentialParsingError.JwtVcIssuerMismatch };
            }
        }
        return undefined;
    }
    catch (err) {
        return { code: error_1.CredentialParsingError.JwtVcIssuerFail };
    }
}
function isValidHttpUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol.startsWith('http');
    }
    catch {
        return false;
    }
}
function isCredentialPayload(obj) {
    return typeof obj === 'object' && obj !== null && 'iss' in obj && typeof obj.iss === 'string';
}
async function getSdJwtVcMetadata(context, httpClient, credential, parsedClaims, warnings = []) {
    try {
        // Decode Header
        let credentialHeader;
        try {
            credentialHeader = JSON.parse(new TextDecoder().decode((0, util_1.fromBase64Url)(credential.split('.')[0])));
        }
        catch (e) {
            console.warn('Failed to decode credential header:', e);
            const resultCode = handleMetadataCode(error_1.CredentialParsingError.HeaderFail, warnings);
            if (resultCode)
                return resultCode;
        }
        if (!credentialHeader || typeof credentialHeader !== 'object') {
            console.warn('Invalid or missing credential header structure.');
            return { error: error_1.CredentialParsingError.HeaderFail };
        }
        const credentialPayload = parsedClaims;
        if (!credentialPayload || !isCredentialPayload(credentialPayload)) {
            return { error: error_1.CredentialParsingError.PayloadFail };
        }
        const vct = credentialPayload.vct;
        if (vct && typeof vct === 'string' && isValidHttpUrl(vct)) {
            // Check jwt-vc-issuer by iss
            const checkIssuer = await resolveIssuerMetadata(httpClient, credentialPayload.iss);
            if (checkIssuer) {
                const resultCode = handleMetadataCode(checkIssuer.code, warnings);
                if (resultCode)
                    return resultCode;
            }
            try {
                const vctIntegrity = credentialPayload['vct#integrity'];
                const mergedMetadata = await fetchAndMergeMetadata(context, httpClient, vct, undefined, new Set(), vctIntegrity, credentialPayload, warnings);
                if (mergedMetadata) {
                    if ('error' in mergedMetadata) {
                        return { error: mergedMetadata.error };
                    }
                    else {
                        return { credentialMetadata: mergedMetadata, warnings };
                    }
                }
            }
            catch (e) {
                console.warn('Invalid vct URL:', vct, e);
            }
        }
        if (credentialHeader.vctm && Array.isArray(credentialHeader.vctm)) {
            const decodedVctmList = credentialHeader.vctm.map((encoded, index) => {
                try {
                    return JSON.parse(new TextDecoder().decode((0, util_1.fromBase64Url)(encoded)));
                }
                catch (err) {
                    return { error: "VctmDecodeFail" };
                }
            });
            const vctIntegrity = credentialPayload['vct#integrity'];
            const vctmMergedMetadata = await fetchAndMergeMetadata(context, httpClient, credentialPayload.vct, decodedVctmList, new Set(), vctIntegrity, credentialPayload, warnings);
            if (vctmMergedMetadata) {
                if ('error' in vctmMergedMetadata) {
                    return { error: vctmMergedMetadata.error };
                }
                else {
                    console.log('Final vctm Metadata:', vctmMergedMetadata);
                    return { credentialMetadata: vctmMergedMetadata, warnings };
                }
            }
        }
        // if no metafata found return NotFound
        // here you add more ways to find metadata (eg registry)
        warnings.push({ code: error_1.CredentialParsingError.NotFound });
        return { credentialMetadata: undefined, warnings };
    }
    catch (err) {
        console.log(err);
        return { error: error_1.CredentialParsingError.UnknownError };
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2V0U2RKd3RWY01ldGFkYXRhLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3V0aWxzL2dldFNkSnd0VmNNZXRhZGF0YS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQTZGQSxzREErQkM7QUE0SUQsc0RBd0JDO0FBZUQsZ0RBK0VDO0FBN1hELGlDQUFtRDtBQUNuRCwrREFBNEQ7QUFDNUQsMERBQW9DO0FBQ3BDLDhEQUFxQztBQUVyQyxvQ0FBMEc7QUFFMUcsU0FBUyxrQkFBa0IsQ0FDMUIsSUFBNEIsRUFDNUIsUUFBMkI7SUFHM0IsSUFBSSxJQUFBLG1DQUEyQixFQUFDLElBQUksQ0FBQyxFQUFFLENBQUM7UUFDdkMsUUFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7UUFDeEIsT0FBTyxTQUFTLENBQUMsQ0FBQyxnQkFBZ0I7SUFDbkMsQ0FBQztTQUFNLENBQUM7UUFDUCxPQUFPLENBQUMsSUFBSSxDQUFDLHFCQUFxQixJQUFJLEdBQUcsQ0FBQyxDQUFDO1FBQzNDLE9BQU8sRUFBRSxLQUFLLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQyxZQUFZO0lBQ3JDLENBQUM7QUFDRixDQUFDO0FBRUQsU0FBUyxTQUFTLENBQUMsTUFBVyxFQUFFLEtBQVU7SUFFekMsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLEVBQUUsQ0FBQztRQUNuRCwwQkFBMEI7UUFDMUIsSUFBSSxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsSUFBSSxJQUFJLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxJQUFJLEVBQUUsQ0FBQztZQUN2QyxNQUFNLEdBQUcsR0FBRyxJQUFJLEdBQUcsRUFBZSxDQUFDO1lBRW5DLEtBQUssTUFBTSxJQUFJLElBQUksTUFBTSxFQUFFLENBQUM7Z0JBQzNCLEdBQUcsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFD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