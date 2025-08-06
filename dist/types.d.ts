import { CredentialParsingError } from "./error";
export declare enum VerifiableCredentialFormat {
    VC_SDJWT = "vc+sd-jwt",
    DC_SDJWT = "dc+sd-jwt",
    MSO_MDOC = "mso_mdoc"
}
export type CredentialIssuer = {
    id: string;
    name: string;
};
export type CredentialClaims = Record<string, unknown>;
export type Result<T, E> = {
    success: true;
    value: T;
} | {
    success: false;
    error: E;
};
export type ParserResult = {
    success: true;
    value: ParsedCredential;
} | {
    success: false;
    error: CredentialParsingError;
};
export type CredentialPayload = {
    iss: string;
    vct: string;
    [key: string]: unknown;
};
export type MetadataError = {
    error: CredentialParsingError;
};
export type MetadataWarning = {
    code: CredentialParsingError;
};
export type CredentialClaimPath = Array<string>;
export type CredentialFriendlyNameCallback = (preferredLangs?: string[]) => Promise<string | null>;
export type ImageDataUriCallback = (filter?: Array<CredentialClaimPath>, preferredLangs?: string[]) => Promise<string | null>;
export type ParsedCredential = {
    metadata: {
        credential: {
            format: VerifiableCredentialFormat.VC_SDJWT | VerifiableCredentialFormat.DC_SDJWT;
            vct: string;
            name: CredentialFriendlyNameCallback;
            metadataDocuments: Record<string, unknown>[];
            image: {
                dataUri: ImageDataUriCallback;
            };
        } | {
            format: VerifiableCredentialFormat.MSO_MDOC;
            doctype: string;
            name: CredentialFriendlyNameCallback;
            image: {
                dataUri: ImageDataUriCallback;
            };
        };
        issuer: CredentialIssuer;
    };
    validityInfo: {
        validUntil?: Date;
        validFrom?: Date;
        signed?: Date;
    };
    signedClaims: CredentialClaims;
    warnings?: Array<MetadataWarning>;
};
//# sourceMappingURL=types.d.ts.map