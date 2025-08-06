"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SDJWTVCVerifier = SDJWTVCVerifier;
const core_1 = require("@sd-jwt/core");
const sd_jwt_vc_1 = require("@sd-jwt/sd-jwt-vc");
const error_1 = require("../error");
const jose_1 = require("jose");
const util_1 = require("../utils/util");
const verifyCertificate_1 = require("../utils/verifyCertificate");
function SDJWTVCVerifier(args) {
    let errors = [];
    const logError = (error, message) => {
        errors.push({ error, message });
    };
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    // Encoding the string into a Uint8Array
    const hasherAndAlgorithm = {
        hasher: (data, alg) => {
            const encoded = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
            return args.context.subtle.digest(alg, encoded).then((v) => new Uint8Array(v));
        },
        alg: 'sha-256',
    };
    const parse = async (rawCredential) => {
        try {
            const credential = await core_1.SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher);
            const parsedSdJwtWithPrettyClaims = await (await core_1.SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher)).getClaims(hasherAndAlgorithm.hasher);
            return { credential, parsedSdJwtWithPrettyClaims };
        }
        catch (err) {
            if (err instanceof Error) {
                logError(error_1.CredentialVerificationError.InvalidFormat, "Invalid format. Error: " + err.name + ": " + err.message);
            }
            return error_1.CredentialVerificationError.InvalidFormat;
        }
    };
    const getHolderPublicKey = async (rawCredential) => {
        const parseResult = await parse(rawCredential);
        if (parseResult === error_1.CredentialVerificationError.InvalidFormat) {
            return {
                success: false,
                error: error_1.CredentialVerificationError.InvalidFormat,
            };
        }
        const cnf = parseResult.parsedSdJwtWithPrettyClaims.cnf;
        if (cnf.jwk && parseResult.credential.jwt && parseResult.credential.jwt.header && typeof parseResult.credential.jwt.header["alg"] === 'string') {
            try {
                const holderPublicKey = await (0, jose_1.importJWK)(cnf.jwk, parseResult.credential.jwt.header["alg"]);
                return {
                    success: true,
                    value: holderPublicKey,
                };
            }
            catch (err) {
                logError(error_1.CredentialVerificationError.CannotImportHolderPublicKey, `Error on getHolderPublicKey(): Could not import holder's public key. Cause: ${err.message}`);
                return {
                    success: false,
                    error: error_1.CredentialVerificationError.CannotImportHolderPublicKey,
                };
            }
        }
        return {
            success: false,
            error: error_1.CredentialVerificationError.CannotExtractHolderPublicKey
        };
    };
    const verifyIssuerSignature = async (rawCredential) => {
        const parsedSdJwt = await (async () => {
            try {
                return (await core_1.SDJwt.fromEncode(rawCredential, hasherAndAlgorithm.hasher)).jwt;
            }
            catch (err) {
                if (err instanceof Error) {
                    logError(error_1.CredentialVerificationError.InvalidFormat, "Invalid format. Error: " + err.name + ": " + err.message);
                }
                return error_1.CredentialVerificationError.InvalidFormat;
            }
        })();
        if (parsedSdJwt === error_1.CredentialVerificationError.InvalidFormat) {
            logError(error_1.CredentialVerificationError.InvalidFormat, "Invalid format");
            return {
                success: false,
                error: error_1.CredentialVerificationError.InvalidFormat
            };
        }
        const getIssuerPublicKey = async () => {
            const x5c = parsedSdJwt?.header?.x5c ?? "";
            const alg = parsedSdJwt?.header?.alg ?? "";
            if (x5c && x5c instanceof Array && x5c.length > 0 && typeof alg === 'string') { // extract public key from certificate
                const lastCertificate = x5c[x5c.length - 1];
                const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;
                const certificateValidationResult = await (0, verifyCertificate_1.verifyCertificate)(lastCertificatePem, args.context.trustedCertificates);
                const lastCertificateIsRootCa = args.context.trustedCertificates.map((c) => c.trim()).includes(lastCertificatePem);
                const rootCertIsTrusted = certificateValidationResult === true || lastCertificateIsRootCa;
                if (!rootCertIsTrusted) {
                    logError(error_1.CredentialVerificationError.NotTrustedIssuer, "Error on getIssuerPublicKey(): Issuer is not trusted");
                    return {
                        success: false,
                        error: error_1.CredentialVerificationError.NotTrustedIssuer,
                    };
                }
                try {
                    const issuerPemCert = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
                    const issuerPublicKey = await (0, jose_1.importX509)(issuerPemCert, alg);
                    return {
                        success: true,
                        value: issuerPublicKey,
                    };
                }
                catch (err) {
                    logError(error_1.CredentialVerificationError.CannotImportIssuerPublicKey, `Error on getIssuerPublicKey(): Importing key failed because: ${err}`);
                    return {
                        success: false,
                        error: error_1.CredentialVerificationError.CannotImportIssuerPublicKey,
                    };
                }
            }
            if (parsedSdJwt && parsedSdJwt.payload && typeof parsedSdJwt.payload.iss === 'string' && typeof alg === 'string') {
                const publicKeyResolutionResult = await args.pkResolverEngine.resolve({ identifier: parsedSdJwt.payload.iss });
                if (!publicKeyResolutionResult.success) {
                    logError(error_1.CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
                    return {
                        success: false,
                        error: error_1.CredentialVerificationError.CannotResolveIssuerPublicKey,
                    };
                }
                try {
                    const publicKey = await (0, jose_1.importJWK)(publicKeyResolutionResult.value.jwk, alg);
                    return {
                        success: true,
                        value: publicKey,
                    };
                }
                catch (err) {
                    logError(error_1.CredentialVerificationError.CannotImportIssuerPublicKey, `Error on getIssuerPublicKey(): Cannot import issuer's public key after resolved from the resolver. Cause ${err.message}`);
                    return {
                        success: false,
                        error: error_1.CredentialVerificationError.CannotImportIssuerPublicKey,
                    };
                }
            }
            logError(error_1.CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
            return {
                success: false,
                error: error_1.CredentialVerificationError.CannotResolveIssuerPublicKey,
            };
        };
        const issuerPublicKeyResult = await getIssuerPublicKey();
        if (!issuerPublicKeyResult.success) {
            logError(error_1.CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
            return {
                success: false,
                error: issuerPublicKeyResult.error,
            };
        }
        const publicKey = issuerPublicKeyResult.value;
        try {
            await (0, jose_1.jwtVerify)(rawCredential.split('~')[0], publicKey, { clockTolerance: args.context.clockTolerance });
        }
        catch (err) {
            if (err instanceof Error && err.name == "JWTExpired") {
                logError(error_1.CredentialVerificationError.ExpiredCredential, `Error on verifyIssuerSignature(): Credential is expired. Cause: ${err}`);
                return {
                    success: false,
                    error: error_1.CredentialVerificationError.ExpiredCredential,
                };
            }
            logError(error_1.CredentialVerificationError.InvalidSignature, `Error on verifyIssuerSignature(): Issuer signature verification failed. Cause: ${err}`);
            return {
                success: false,
                error: error_1.CredentialVerificationError.InvalidSignature,
            };
        }
        return {
            success: true,
            value: {},
        };
    };
    const fetchVctFromRegistry = async function (urnOrUrl, integrity) {
        if (urnOrUrl.startsWith('https')) {
            const url = urnOrUrl;
            return await args.httpClient.get(url).then(({ data }) => {
                return data;
            });
        }
        if (urnOrUrl.startsWith('urn')) {
            const urn = urnOrUrl;
            const SdJwtVc = new sd_jwt_vc_1.SDJwtVcInstance({
                hasher: hasherAndAlgorithm.hasher,
            });
            const uri = args.context.config?.vctRegistryUri;
            if (!uri) {
                throw new Error(error_1.CredentialVerificationError.VctRegistryNotConfigured);
            }
            const vctm = await args.httpClient.get(uri)
                .then(({ data }) => data)
                .then(vctmList => {
                return vctmList.find(({ vct: current }) => current === urn);
            });
            if (!vctm) {
                throw new Error(error_1.CredentialVerificationError.VctUrnNotFoundError);
            }
            // @ts-ignore
            const isIntegrityValid = await SdJwtVc.validateIntegrity(vctm, uri, integrity);
            return vctm;
        }
        throw new Error('vct is neither an URL nor an urn');
    };
    const verifyCredentialVct = async (rawCredential) => {
        const SdJwtVc = new sd_jwt_vc_1.SDJwtVcInstance({
            verifier: () => true,
            hasher: hasherAndAlgorithm.hasher,
            hashAlg: hasherAndAlgorithm.alg,
            loadTypeMetadataFormat: true,
            vctFetcher: fetchVctFromRegistry,
        });
        try {
            const verified = await SdJwtVc.verify(rawCredential);
            if (!verified.payload) {
                return {
                    success: false,
                    error: error_1.CredentialVerificationError.VctSchemaError,
                };
            }
        }
        catch (error) {
            console.error(error);
            if (error instanceof Error && error.message == error_1.CredentialVerificationError.VctUrnNotFoundError) {
                return {
                    success: true,
                    value: {},
                };
            }
            else {
                return {
                    success: false,
                    error: error_1.CredentialVerificationError.VctSchemaError,
                };
            }
        }
        return {
            success: true,
            value: {},
        };
    };
    const verifyKbJwt = async (rawPresentation, opts) => {
        const kbJwt = rawPresentation.split('~')[rawPresentation.split('~').length - 1];
        let temp = rawPresentation.split('~');
        temp = temp.slice(0, temp.length - 1);
        const rawCredentialWithoutKbJwt = temp.join('~') + '~';
        const publicKeyResult = await getHolderPublicKey(rawCredentialWithoutKbJwt);
        if (!publicKeyResult.success) {
            logError(error_1.CredentialVerificationError.CannotExtractHolderPublicKey, "CannotExtractHolderPublicKey");
            return {
                success: false,
                error: publicKeyResult.error,
            };
        }
        const holderPublicKey = publicKeyResult.value;
        const kbJwtDecodedPayload = JSON.parse(decoder.decode((0, util_1.fromBase64Url)(kbJwt.split('.')[1])));
        if (!kbJwtDecodedPayload.sd_hash || !kbJwtDecodedPayload.nonce || !kbJwtDecodedPayload.aud) {
            logError(error_1.CredentialVerificationError.KbJwtVerificationFailedMissingParameters, "Error on verifyKbJwt(): Once of sd_hash, nonce and aud are missing from the kbjwt payload");
            return {
                success: false,
                error: error_1.CredentialVerificationError.KbJwtVerificationFailedMissingParameters,
            };
        }
        const { sd_hash, nonce, aud } = kbJwtDecodedPayload;
        const data = encoder.encode(rawCredentialWithoutKbJwt);
        const hashBuffer = await args.context.subtle.digest('SHA-256', data);
        const calculatedSdHash = (0, util_1.toBase64Url)(hashBuffer);
        if (calculatedSdHash !== sd_hash) {
            logError(error_1.CredentialVerificationError.KbJwtVerificationFailedWrongSdHash, "Error on verifyKbJwt(): Invalid sd_hash");
            return {
                success: false,
                error: error_1.CredentialVerificationError.KbJwtVerificationFailedWrongSdHash,
            };
        }
        if (opts.expectedAudience && opts.expectedAudience !== aud) {
            logError(error_1.CredentialVerificationError.KbJwtVerificationFailedUnexpectedAudience, "Error on verifyKbJwt(): Invalid aud");
            return {
                success: false,
                error: error_1.CredentialVerificationError.KbJwtVerificationFailedUnexpectedAudience,
            };
        }
        if (opts.expectedNonce && opts.expectedNonce !== nonce) {
            logError(error_1.CredentialVerificationError.KbJwtVerificationFailedUnexpectedNonce, "Error on verifyKbJwt(): Invalid nonce");
            return {
                success: false,
                error: error_1.CredentialVerificationError.KbJwtVerificationFailedUnexpectedNonce,
            };
        }
        try {
            await (0, jose_1.jwtVerify)(kbJwt, holderPublicKey, { clockTolerance: args.context.clockTolerance });
        }
        catch (err) {
            logError(error_1.CredentialVerificationError.KbJwtVerificationFailedSignatureValidation, "Error on verifyKbJwt(): Invalid KB-JWT signature");
            return {
                success: false,
                error: error_1.CredentialVerificationError.KbJwtVerificationFailedSignatureValidation,
            };
        }
        return {
            success: true,
            value: {},
        };
    };
    return {
        async verify({ rawCredential, opts }) {
            errors = []; // re-initialize error array
            if (typeof rawCredential !== 'string') {
                return {
                    success: false,
                    error: error_1.CredentialVerificationError.InvalidDatatype,
                };
            }
            // Issuer Signature validation
            const issuerSignatureVerificationResult = await verifyIssuerSignature(rawCredential);
            if (!issuerSignatureVerificationResult.success) {
                return {
                    success: false,
                    error: errors.length > 0 ? errors[0].error : error_1.CredentialVerificationError.UnknownProblem,
                };
            }
            // Credential vct validation
            if (opts.verifySchema) {
                const credentialVctVerificationResult = await verifyCredentialVct(rawCredential);
                if (!credentialVctVerificationResult.success) {
                    return {
                        success: false,
                        error: errors.length > 0 ? errors[0].error : error_1.CredentialVerificationError.UnknownProblem,
                    };
                }
            }
            // KB-JWT validation
            if (!rawCredential.endsWith('~')) { // contains kbjwt
                const verifyKbJwtResult = await verifyKbJwt(rawCredential, opts);
                if (!verifyKbJwtResult.success) {
                    return {
                        success: false,
                        error: errors.length > 0 ? errors[0].error : error_1.CredentialVerificationError.UnknownProblem,
                    };
                }
            }
            const publicKeyResult = await getHolderPublicKey(rawCredential);
            if (publicKeyResult.success === false) {
                logError(error_1.CredentialVerificationError.CannotExtractHolderPublicKey, "Could not extract holder public key");
                return {
                    success: false,
                    error: errors.length > 0 ? errors[0].error : error_1.CredentialVerificationError.UnknownProblem,
                };
            }
            return {
                success: true,
                value: {
                    valid: true,
                    holderPublicKey: await (0, jose_1.exportJWK)(publicKeyResult.value),
                },
            };
        },
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiU0RKV1RWQ1ZlcmlmaWVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2NyZWRlbnRpYWwtdmVyaWZpZXJzL1NESldUVkNWZXJpZmllci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQVVBLDBDQWlaQztBQTNaRCx1Q0FBcUM7QUFDckMsaURBQW9EO0FBR3BELG9DQUF1RDtBQUV2RCwrQkFBaUY7QUFDakYsd0NBQTJEO0FBQzNELGtFQUErRDtBQUUvRCxTQUFnQixlQUFlLENBQUMsSUFBOEY7SUFDN0gsSUFBSSxNQUFNLEdBQThELEVBQUUsQ0FBQztJQUMzRSxNQUFNLFFBQVEsR0FBRyxDQUFDLEtBQWtDLEVBQUUsT0FBZSxFQUFRLEVBQUU7UUFDOUUsTUFBTSxDQUFDLElBQUksQ0FBQyxFQUFFLEtBQUssRUFBRSxPQUFPLEVBQUUsQ0FBQyxDQUFDO0lBQ2pDLENBQUMsQ0FBQTtJQUVELE1BQU0sT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUM7SUFDbEMsTUFBTSxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUUsQ0FBQztJQUVsQyx3Q0FBd0M7SUFDeEMsTUFBTSxrQkFBa0IsR0FBaUI7UUFDeEMsTUFBTSxFQUFFLENBQUMsSUFBMEIsRUFBRSxHQUFXLEVBQUUsRUFBRTtZQUNuRCxNQUFNLE9BQU8sR0FDWixPQUFPLElBQUksS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFDO1lBRXhFLE9BQU8sSUFBSSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxPQUFPLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLElBQUksVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFDaEYsQ0FBQztRQUNELEdBQUcsRUFBRSxTQUFTO0tB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