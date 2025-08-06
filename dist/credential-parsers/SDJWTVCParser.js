"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SDJWTVCParser = SDJWTVCParser;
const core_1 = require("@sd-jwt/core");
const error_1 = require("../error");
const types_1 = require("../types");
const schemas_1 = require("../schemas");
const rendering_1 = require("../rendering");
const getSdJwtVcMetadata_1 = require("../utils/getSdJwtVcMetadata");
const openID4VCICredentialRendering_1 = require("../functions/openID4VCICredentialRendering");
const zod_1 = require("zod");
const getIssuerMetadata_1 = require("../utils/getIssuerMetadata");
const matchLocalizedDisplay_1 = require("../utils/matchLocalizedDisplay");
function SDJWTVCParser(args) {
    const encoder = new TextEncoder();
    function extractValidityInfo(jwtPayload) {
        let obj = {};
        if (jwtPayload.exp) {
            obj = {
                ...obj,
                validUntil: new Date(jwtPayload.exp * 1000),
            };
        }
        if (jwtPayload.iat) {
            obj = {
                ...obj,
                signed: new Date(jwtPayload.iat * 1000),
            };
        }
        if (jwtPayload.nbf) {
            obj = {
                ...obj,
                validFrom: new Date(jwtPayload.nbf * 1000),
            };
        }
        return obj;
    }
    // Encoding the string into a Uint8Array
    const hasherAndAlgorithm = {
        hasher: (data, alg) => {
            const encoded = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
            return args.context.subtle.digest(alg, encoded).then((v) => new Uint8Array(v));
        },
        alg: 'sha-256',
    };
    const cr = (0, rendering_1.CredentialRenderingService)();
    const renderer = (0, openID4VCICredentialRendering_1.OpenID4VCICredentialRendering)({ httpClient: args.httpClient });
    return {
        async parse({ rawCredential }) {
            if (typeof rawCredential !== 'string') {
                return {
                    success: false,
                    error: error_1.CredentialParsingError.InvalidDatatype
                };
            }
            let credentialFriendlyName = async () => null;
            let dataUri = async () => null;
            const warnings = [];
            const { parsedClaims, parsedHeaders, err } = await (async () => {
                try {
                    const parsedSdJwt = await core_1.SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher);
                    const claims = await parsedSdJwt.getClaims(hasherAndAlgorithm.hasher);
                    const headers = await parsedSdJwt.jwt?.header;
                    return { parsedClaims: claims, parsedHeaders: headers, err: null };
                }
                catch (err) {
                    return { parsedClaims: null, parsedHeaders: null, err: err };
                }
            })();
            if (err || !parsedClaims || !parsedHeaders) {
                return {
                    success: false,
                    error: error_1.CredentialParsingError.CouldNotParse,
                };
            }
            const schema = zod_1.z.enum([types_1.VerifiableCredentialFormat.VC_SDJWT, types_1.VerifiableCredentialFormat.DC_SDJWT]);
            const typParseResult = await schema.safeParseAsync(parsedHeaders.typ);
            if (typParseResult.error) {
                return {
                    success: false,
                    error: error_1.CredentialParsingError.NotSupportedCredentialType,
                };
            }
            // sd-jwt vc Payload Schema Validation
            let validatedParsedClaims;
            try {
                validatedParsedClaims = schemas_1.SdJwtVcPayloadSchema.parse(parsedClaims);
            }
            catch (err) {
                return {
                    success: false,
                    error: error_1.CredentialParsingError.InvalidSdJwtVcPayload,
                };
            }
            const { metadata: issuerMetadata } = await (0, getIssuerMetadata_1.getIssuerMetadata)(args.httpClient, validatedParsedClaims.iss, warnings);
            const getSdJwtMetadataResult = await (0, getSdJwtVcMetadata_1.getSdJwtVcMetadata)(args.context, args.httpClient, rawCredential, validatedParsedClaims, warnings);
            if ('error' in getSdJwtMetadataResult) {
                return {
                    success: false,
                    error: getSdJwtMetadataResult.error,
                };
            }
            else if (getSdJwtMetadataResult.credentialMetadata) {
                const { credentialMetadata } = getSdJwtMetadataResult;
                credentialFriendlyName = async (preferredLangs = ['en-US']) => {
                    const vct = credentialMetadata.vct;
                    const credentialDisplayArray = credentialMetadata.display;
                    const issuerDisplayArray = vct
                        ? issuerMetadata?.credential_configurations_supported?.[vct]?.display
                        : undefined;
                    const credentialDisplayLocalized = (0, matchLocalizedDisplay_1.matchDisplayByLang)(credentialDisplayArray, preferredLangs);
                    //@ts-ignore
                    if (credentialDisplayLocalized?.name)
                        return credentialDisplayLocalized.name;
                    const issuerDisplayLocalized = (0, matchLocalizedDisplay_1.matchDisplayByLocale)(issuerDisplayArray, preferredLangs);
                    if (issuerDisplayLocalized?.name)
                        return issuerDisplayLocalized.name;
                    return 'SD-JWT Verifiable Credential';
                };
                dataUri = async (filter, preferredLangs = ['en-US']) => {
                    // 1. Try to match localized credential display
                    const credentialDisplayArray = credentialMetadata?.display;
                    const credentialDisplayLocalized = (0, matchLocalizedDisplay_1.matchDisplayByLang)(credentialDisplayArray, preferredLangs);
                    // 2. Try to match localized issuer display
                    const issuerDisplayArray = issuerMetadata?.credential_configurations_supported?.[credentialMetadata.vct]?.display;
                    const issuerDisplayLocalized = (0, matchLocalizedDisplay_1.matchDisplayByLocale)(issuerDisplayArray, preferredLangs);
                    //@ts-ignore
                    const svgTemplateUri = credentialDisplayLocalized?.rendering?.svg_templates?.[0]?.uri || null;
                    //@ts-ignore
                    const simpleDisplayConfig = credentialDisplayLocalized?.rendering?.simple || null;
                    // 1. Try SVG template rendering
                    if (svgTemplateUri) {
                        const svgResponse = await args.httpClient.get(svgTemplateUri, {}, { useCache: true }).catch(() => null);
                        if (svgResponse && svgResponse.status === 200) {
                            const svgdata = svgResponse.data;
                            const rendered = await cr.renderSvgTemplate({
                                json: validatedParsedClaims,
                                credentialImageSvgTemplate: svgdata,
                                sdJwtVcMetadataClaims: credentialMetadata.claims,
                                filter,
                            }).catch(() => null);
                            if (rendered)
                                return rendered;
                        }
                    }
                    // 2. Fallback: simple rendering from credential display
                    if (simpleDisplayConfig && credentialDisplayLocalized) {
                        const rendered = await renderer.renderCustomSvgTemplate({
                            signedClaims: validatedParsedClaims,
                            displayConfig: { ...credentialDisplayLocalized, ...simpleDisplayConfig },
                        }).catch(() => null);
                        if (rendered)
                            return rendered;
                    }
                    // 3. Fallback: rendering from issuer metadata display
                    if (issuerDisplayLocalized) {
                        const rendered = await renderer.renderCustomSvgTemplate({
                            signedClaims: validatedParsedClaims,
                            displayConfig: issuerDisplayLocalized,
                        }).catch(() => null);
                        if (rendered)
                            return rendered;
                    }
                    const rendered = await renderer.renderCustomSvgTemplate({
                        signedClaims: validatedParsedClaims,
                        displayConfig: { name: "SD-JWT Verifiable Credential" },
                    }).catch(() => null);
                    if (rendered)
                        return rendered;
                    // All attempts failed
                    return null;
                };
            }
            return {
                success: true,
                value: {
                    signedClaims: validatedParsedClaims,
                    metadata: {
                        credential: {
                            format: typParseResult.data,
                            vct: validatedParsedClaims?.vct ?? "",
                            // @ts-ignore
                            metadataDocuments: [getSdJwtMetadataResult.credentialMetadata],
                            image: {
                                dataUri: dataUri,
                            },
                            name: credentialFriendlyName,
                        },
                        issuer: {
                            id: validatedParsedClaims.iss,
                            name: validatedParsedClaims.iss,
                        }
                    },
                    validityInfo: {
                        ...extractValidityInfo(validatedParsedClaims)
                    },
                    warnings: getSdJwtMetadataResult.warnings
                }
            };
        },
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiU0RKV1RWQ1BhcnNlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jcmVkZW50aWFsLXBhcnNlcnMvU0RKV1RWQ1BhcnNlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQWFBLHNDQXdOQztBQXJPRCx1Q0FBcUM7QUFFckMsb0NBQWtEO0FBRWxELG9DQUFrSjtBQUNsSix3Q0FBa0Q7QUFDbEQsNENBQTBEO0FBQzFELG9FQUFpRTtBQUNqRSw4RkFBMkY7QUFDM0YsNkJBQXdCO0FBQ3hCLGtFQUErRDtBQUMvRCwwRUFBMEY7QUFFMUYsU0FBZ0IsYUFBYSxDQUFDLElBQWtEO0lBQy9FLE1BQU0sT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUM7SUFFbEMsU0FBUyxtQkFBbUIsQ0FBQyxVQUF3RDtRQUNwRixJQUFJLEdBQUcsR0FBRyxFQUFFLENBQUM7UUFDYixJQUFJLFVBQVUsQ0FBQyxHQUFHLEVBQUUsQ0FBQztZQUNwQixHQUFHLEdBQUc7Z0JBQ0wsR0FBRyxHQUFHO2dCQUNOLFVBQVUsRUFBRSxJQUFJLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxHQUFHLElBQUksQ0FBQzthQUMzQyxDQUFBO1FBQ0YsQ0FBQztRQUNELElBQUksVUFBVSxDQUFDLEdBQUcsRUFBRSxDQUFDO1lBQ3BCLEdBQUcsR0FBRztnQkFDTCxHQUFHLEdBQUc7Z0JBQ04sTUFBTSxFQUFFLElBQUksSUFBSSxDQUFDLFVBQVUsQ0FBQyxHQUFHLEdBQUcsSUFBSSxDQUFDO2FBQ3ZDLENBQUE7UUFDRixDQUFDO1FBRUQsSUFBSSxVQUFVLENBQUMsR0FBRyxFQUFFLENBQUM7WUFDcEIsR0FBRyxHQUFHO2dCQUNMLEdBQUcsR0FBRztnQkFDTixTQUFTLEVBQUUsSUFBSSxJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsR0FBRyxJQUFJLENBQUM7YUFDMUMsQ0FBQTtRQUNGLENBQUM7UUFDRCxPQUFPLEdBQUcsQ0FBQztJQUNaLENBQUM7SUFFRCx3Q0FBd0M7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