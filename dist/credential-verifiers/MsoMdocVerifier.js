"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MsoMdocVerifier = MsoMdocVerifier;
const error_1 = require("../error");
const util_1 = require("../utils/util");
const mdl_1 = require("@auth0/mdl");
const cbor_1 = require("@auth0/mdl/lib/cbor/");
const cose_kit_1 = require("cose-kit");
function MsoMdocVerifier(args) {
    let errors = [];
    const logError = (error, message) => {
        errors.push({ error, message });
    };
    const verifier = new mdl_1.Verifier(args.context.trustedCertificates.map((crt) => `-----BEGIN CERTIFICATE-----\n${crt}\n-----END CERTIFICATE-----`));
    const getSessionTranscriptBytesForOID4VPHandover = async (clId, respUri, nonce, mdocNonce) => (0, cbor_1.cborEncode)(mdl_1.DataItem.fromData([
        null,
        null,
        [
            await args.context.subtle.digest('SHA-256', (0, cbor_1.cborEncode)([clId, mdocNonce])),
            await args.context.subtle.digest('SHA-256', (0, cbor_1.cborEncode)([respUri, mdocNonce])),
            nonce
        ]
    ]));
    async function expirationCheck(issuerSigned) {
        const { validFrom, validUntil, signed } = issuerSigned.issuerAuth.decodedPayload.validityInfo;
        if (Math.floor(validUntil.getTime() / 1000) + args.context.clockTolerance < Math.floor(new Date().getTime() / 1000)) {
            logError(error_1.CredentialVerificationError.ExpiredCredential, "Credential is expired");
            return error_1.CredentialVerificationError.ExpiredCredential;
        }
        return null;
    }
    function extractHolderPublicKeyJwk(parsedDocument) {
        if (parsedDocument.issuerSigned.issuerAuth.decodedPayload.deviceKeyInfo == undefined) {
            logError(error_1.CredentialVerificationError.MsoMdocMissingDeviceKeyInfo, "MsoMdocMissingDeviceKeyInfo");
            return null;
        }
        const cosePublicKey = parsedDocument.issuerSigned.issuerAuth.decodedPayload.deviceKeyInfo.deviceKey;
        const holderPublicKeyJwk = (0, cose_kit_1.COSEKeyToJWK)(cosePublicKey);
        return holderPublicKeyJwk;
    }
    async function issuerSignedCheck(rawCredential) {
        try {
            const credentialBytes = (0, util_1.fromBase64Url)(rawCredential);
            const issuerSigned = (0, cbor_1.cborDecode)(credentialBytes);
            const [header, _, payload, sig] = issuerSigned.get('issuerAuth');
            const decodedIssuerAuthPayload = (0, cbor_1.cborDecode)(payload);
            const docType = decodedIssuerAuthPayload.data.get('docType');
            const m = {
                version: '1.0',
                documents: [new Map([
                        ['docType', docType],
                        ['issuerSigned', issuerSigned]
                    ])],
                status: 0
            };
            const encoded = (0, cbor_1.cborEncode)(m);
            const mdoc = (0, mdl_1.parse)(encoded);
            const [parsedDocument] = mdoc.documents;
            const expirationCheckRes = await expirationCheck(parsedDocument.issuerSigned);
            if (expirationCheckRes !== null) {
                return { holderPublicKeyJwk: null };
            }
            if (parsedDocument.issuerSigned.issuerAuth.x5chain && args.context.trustedCertificates.length > 0) {
                const { publicKey } = await parsedDocument.issuerSigned.issuerAuth.verifyX509Chain(args.context.trustedCertificates);
                if (!publicKey) {
                    logError(error_1.CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
                    return { holderPublicKeyJwk: null };
                }
                const verification = await parsedDocument.issuerSigned.issuerAuth.verify(publicKey);
                if (verification !== true) {
                    logError(error_1.CredentialVerificationError.InvalidSignature, "Invalid signature");
                }
                const holderPublicKeyJwk = extractHolderPublicKeyJwk(parsedDocument);
                return {
                    holderPublicKeyJwk
                };
            }
            const holderPublicKeyJwk = extractHolderPublicKeyJwk(parsedDocument);
            return {
                holderPublicKeyJwk
            };
        }
        catch (err) {
            // @ts-ignore
            if (err?.name && err.name === "X509InvalidCertificateChain") {
                logError(error_1.CredentialVerificationError.InvalidCertificateChain, "Invalid Certificate chain: " + JSON.stringify(err));
            }
        }
        return { holderPublicKeyJwk: null };
    }
    async function deviceResponseCheck(mdoc, opts) {
        try {
            const [parsedDocument] = mdoc.documents;
            if (!parsedDocument.deviceSigned) { // not a DeviceResponse
                return { holderPublicKeyJwk: null };
            }
            if (args.context.trustedCertificates.length > 0) {
                const res = await parsedDocument.issuerSigned.issuerAuth.verifyX509(args.context.trustedCertificates);
                if (!res) {
                    logError(error_1.CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
                    return { holderPublicKeyJwk: null };
                }
            }
            const expiredResult = await expirationCheck(parsedDocument.issuerSigned);
            if (expiredResult) {
                return { holderPublicKeyJwk: null };
            }
            const holderPublicKeyJwk = extractHolderPublicKeyJwk(parsedDocument);
            if (opts.expectedAudience && opts.responseUri && opts.expectedNonce && opts.holderNonce) {
                await verifier.verify(mdoc.encode(), {
                    encodedSessionTranscript: await getSessionTranscriptBytesForOID4VPHandover(opts.expectedAudience, opts.responseUri, opts.expectedNonce, opts.holderNonce)
                });
                return { holderPublicKeyJwk };
            }
            return { holderPublicKeyJwk: holderPublicKeyJwk };
        }
        catch (err) {
            if (err instanceof Error) {
                if (err.name === "X509InvalidCertificateChain") {
                    logError(error_1.CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
                    return { holderPublicKeyJwk: null };
                }
                else if (err.name === "MDLError") {
                    logError(error_1.CredentialVerificationError.InvalidSignature, `MDLError: ${err.message}`);
                }
                else {
                    console.error(err);
                }
            }
            return { holderPublicKeyJwk: null };
        }
    }
    return {
        async verify({ rawCredential, opts }) {
            if (typeof rawCredential !== 'string') {
                return {
                    success: false,
                    error: error_1.CredentialVerificationError.InvalidDatatype,
                };
            }
            try {
                const decodedCred = (0, util_1.fromBase64Url)(rawCredential);
                const parsedMDOC = (0, mdl_1.parse)(decodedCred);
                const { holderPublicKeyJwk } = await deviceResponseCheck(parsedMDOC, opts);
                if (errors.length === 0 && holderPublicKeyJwk !== null) {
                    return {
                        success: true,
                        value: {
                            holderPublicKey: holderPublicKeyJwk,
                        }
                    };
                }
                if (errors.length > 0) {
                    return {
                        success: false,
                        error: errors.length > 0 ? errors[0].error : error_1.CredentialVerificationError.UnknownProblem,
                    };
                }
            }
            catch (err) {
                const { holderPublicKeyJwk } = await issuerSignedCheck(rawCredential);
                if (errors.length === 0 && holderPublicKeyJwk !== null) {
                    return {
                        success: true,
                        value: {
                            holderPublicKey: holderPublicKeyJwk,
                        }
                    };
                }
                if (errors.length > 0) {
                    return {
                        success: false,
                        error: errors.length > 0 ? errors[0].error : error_1.CredentialVerificationError.UnknownProblem,
                    };
                }
            }
            console.error(errors);
            return {
                success: false,
                error: error_1.CredentialVerificationError.UnknownProblem
            };
        },
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTXNvTWRvY1ZlcmlmaWVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2NyZWRlbnRpYWwtdmVyaWZpZXJzL01zb01kb2NWZXJpZmllci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQVVBLDBDQWdPQztBQXpPRCxvQ0FBdUQ7QUFFdkQsd0NBQThDO0FBQzlDLG9DQUF5RztBQUV6RywrQ0FBOEQ7QUFDOUQsdUNBQXdDO0FBR3hDLFNBQWdCLGVBQWUsQ0FBQyxJQUFzRTtJQUNyRyxJQUFJLE1BQU0sR0FBOEQsRUFBRSxDQUFDO0lBQzNFLE1BQU0sUUFBUSxHQUFHLENBQUMsS0FBa0MsRUFBRSxPQUFlLEVBQVEsRUFBRTtRQUM5RSxNQUFNLENBQUMsSUFBSSxDQUFDLEVBQUUsS0FBSyxFQUFFLE9BQU8sRUFBRSxDQUFDLENBQUM7SUFDakMsQ0FBQyxDQUFBO0lBRUQsTUFBTSxRQUFRLEdBQUcsSUFBSSxjQUFRLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRSxDQUMxRSxnQ0FBZ0MsR0FBRyw2QkFBNkIsQ0FDaEUsQ0FBQyxDQUFDO0lBR0gsTUFBTSwwQ0FBMEMsR0FBRyxLQUFLLEVBQUUsSUFBWSxFQUFFLE9BQWUsRUFBRSxLQUFhLEVBQUUsU0FBaUIsRUFBRSxFQUFFLENBQUMsSUFBQSxpQkFBVSxFQUN2SSxjQUFRLENBQUMsUUFBUSxDQUNoQjtRQUNDLElBQUk7UUFDSixJQUFJO1FBQ0o7WUFDQyxNQUFNLElBQUksQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FDL0IsU0FBUyxFQUNULElBQUEsaUJBQVUsRUFBQyxDQUFDLElBQUksRUFBRSxTQUFTLENBQUMsQ0FBQyxDQUM3QjtZQUNELE1BQU0sSUFBSSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUMvQixTQUFTLEVBQ1QsSUFBQSxpQkFBVSxFQUFDLENBQUMsT0FBTyxFQUFF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