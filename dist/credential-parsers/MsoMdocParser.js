"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MsoMdocParser = MsoMdocParser;
const error_1 = require("../error");
const mdl_1 = require("@auth0/mdl");
const util_1 = require("../utils/util");
const types_1 = require("../types");
const cbor_1 = require("@auth0/mdl/lib/cbor");
const openID4VCICredentialRendering_1 = require("../functions/openID4VCICredentialRendering");
function MsoMdocParser(args) {
    function extractValidityInfo(issuerSigned) {
        return issuerSigned.issuerAuth.decodedPayload.validityInfo;
    }
    async function deviceResponseParser(rawCredential) {
        try {
            const decodedCred = (0, util_1.fromBase64Url)(rawCredential);
            const parsedMDOC = (0, mdl_1.parse)(decodedCred);
            const [parsedDocument] = parsedMDOC.documents;
            const namespace = parsedDocument.issuerSignedNameSpaces[0];
            const attrValues = parsedDocument.getIssuerNameSpace(namespace);
            const renderer = (0, openID4VCICredentialRendering_1.OpenID4VCICredentialRendering)({ httpClient: args.httpClient });
            let credentialFriendlyName = async () => null;
            let dataUri = async () => null;
            const mdocDisplayConfig = {
                name: "mdoc Verifiable Credential"
            };
            credentialFriendlyName = async (preferredLangs = ['en-US']) => {
                return 'mdoc Verifiable Credential';
            };
            dataUri = async (filter) => {
                return await renderer.renderCustomSvgTemplate({ signedClaims: attrValues, displayConfig: mdocDisplayConfig })
                    .then((res) => res)
                    .catch((err) => { console.error(err); return null; });
            };
            return {
                metadata: {
                    credential: {
                        format: types_1.VerifiableCredentialFormat.MSO_MDOC,
                        doctype: parsedDocument.docType,
                        image: {
                            dataUri: dataUri,
                        },
                        name: credentialFriendlyName,
                    },
                    issuer: {
                        id: parsedDocument.issuerSigned.issuerAuth.certificate.issuer,
                        name: parsedDocument.issuerSigned.issuerAuth.certificate.issuer
                    }
                },
                signedClaims: {
                    ...attrValues
                },
                validityInfo: {
                    ...extractValidityInfo(parsedDocument.issuerSigned),
                }
            };
        }
        catch (err) {
            return null;
        }
    }
    async function issuerSignedParser(rawCredential) {
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
            const namespace = parsedDocument.issuerSignedNameSpaces[0];
            const attrValues = parsedDocument.getIssuerNameSpace(namespace);
            const renderer = (0, openID4VCICredentialRendering_1.OpenID4VCICredentialRendering)({ httpClient: args.httpClient });
            let credentialFriendlyName = async () => null;
            let dataUri = async () => null;
            const mdocDisplayConfig = {
                name: "mdoc Verifiable Credential"
            };
            credentialFriendlyName = async (preferredLangs = ['en-US']) => {
                return 'mdoc Verifiable Credential';
            };
            dataUri = async (filter, preferredLangs = ['en-US']) => {
                return await renderer.renderCustomSvgTemplate({ signedClaims: attrValues, displayConfig: mdocDisplayConfig })
                    .then((res) => res)
                    .catch((err) => { console.error(err); return null; });
            };
            return {
                metadata: {
                    credential: {
                        format: types_1.VerifiableCredentialFormat.MSO_MDOC,
                        doctype: docType ?? "",
                        image: {
                            dataUri: dataUri,
                        },
                        name: credentialFriendlyName,
                    },
                    issuer: {
                        id: parsedDocument.issuerSigned.issuerAuth.certificate.issuer,
                        name: parsedDocument.issuerSigned.issuerAuth.certificate.issuer
                    }
                },
                signedClaims: {
                    ...attrValues
                },
                validityInfo: {
                    ...extractValidityInfo(parsedDocument.issuerSigned),
                }
            };
        }
        catch (err) {
            return null;
        }
    }
    return {
        async parse({ rawCredential }) {
            if (typeof rawCredential != 'string') {
                return {
                    success: false,
                    error: error_1.CredentialParsingError.InvalidDatatype,
                };
            }
            const deviceResponseParsingResult = await deviceResponseParser(rawCredential);
            if (deviceResponseParsingResult) {
                return {
                    success: true,
                    value: deviceResponseParsingResult
                };
            }
            const issuerSignedParsingResult = await issuerSignedParser(rawCredential);
            if (issuerSignedParsingResult) {
                return {
                    success: true,
                    value: issuerSignedParsingResult,
                };
            }
            return {
                success: false,
                error: error_1.CredentialParsingError.CouldNotParse,
            };
        },
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTXNvTWRvY1BhcnNlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jcmVkZW50aWFsLXBhcnNlcnMvTXNvTWRvY1BhcnNlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQVNBLHNDQThLQztBQXZMRCxvQ0FBa0Q7QUFFbEQsb0NBQW1FO0FBQ25FLHdDQUE4QztBQUM5QyxvQ0FBbUo7QUFDbkosOENBQTZEO0FBRTdELDhGQUEyRjtBQUUzRixTQUFnQixhQUFhLENBQUMsSUFBa0Q7SUFHL0UsU0FBUyxtQkFBbUIsQ0FBQyxZQUEwQjtRQUN0RCxPQUFPLFlBQVksQ0FBQyxVQUFVLENBQUMsY0FBYyxDQUFDLFlBQVksQ0FBQztJQUM1RCxDQUFDO0lBRUQsS0FBSyxVQUFVLG9CQUFvQixDQUFDLGFBQXFCO1FBQ3hELElBQUksQ0FBQztZQUNKLE1BQU0sV0FBVyxHQUFHLElBQUEsb0JBQWEsRUFBQyxhQUFhLENBQUMsQ0FBQTtZQUNoRCxNQUFNLFVBQVUsR0FBRyxJQUFBLFdBQUssRUFBQyxXQUFXLENBQUMsQ0FBQztZQUN0QyxNQUFNLENBQUMsY0FBYyxDQUFDLEdBQUcsVUFBVSxDQUFDLFNBQW1DLENBQUM7WUFDeEUsTUFBTSxTQUFTLEdBQUcsY0FBYyxDQUFDLHNCQUFzQixDQUFDLENBQUMsQ0FBQyxDQUFDO1lBRTNELE1BQU0sVUFBVSxHQUFHLGNBQWMsQ0FBQyxrQkFBa0IsQ0FBQyxTQUFTLENBQUMsQ0FBQztZQUNoRSxNQUFNLFFBQVEsR0FBRyxJQUFBLDZEQUE2QixFQUFDLEVBQUUsVUFBVSxFQUFFLElBQUksQ0FBQyxVQUFVLEVBQUUsQ0FBQyxDQUFDO1lBRWhGLElBQUksc0JBQXNCLEdBQW1DLEtBQUssSUFBSSxFQUFFLENBQUMsSUFBSSxDQUFDO1lBQzlFLElBQUksT0FBTyxHQUF5QixLQUFLLElBQUksRUFBRSxDQUFDLElBQUksQ0FBQztZQUVyRCxNQUFNLGlCQUFpQixHQUFHO2dCQUN6QixJQUFJLEVBQUUsNEJB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