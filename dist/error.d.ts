export declare enum CredentialParsingError {
    CouldNotParse = "CouldNotParse",
    InvalidSdJwtVcPayload = "InvalidSdJwtVcPayload",
    InvalidDatatype = "InvalidDatatype",
    NotSupportedCredentialType = "NotSupportedCredentialType",
    HeaderFail = "HeaderFail",
    SchemaFetchFail = "SchemaFetchFail",
    SchemaConflict = "SchemaConflict",
    InfiniteRecursion = "InfiniteRecursion",
    PayloadFail = "PayloadFail",
    VctmDecodeFail = "VctmDecodeFail",
    UnknownError = "UnknownError",
    NotFound = "NotFound",
    IntegrityMissing = "IntegrityMissing",
    JwtVcIssuerMismatch = "JwtVcIssuerMismatch",
    IntegrityFail = "IntegrityFail",
    SchemaFail = "SchemaFail",
    JwtVcIssuerFail = "JwtVcIssuerFail",
    FailFetchIssuerMetadata = "FailFetchIssuerMetadata",
    FailSchemaIssuerMetadata = "FailSchemaIssuerMetadata"
}
export declare const CredentialParsingWarnings: Set<CredentialParsingError>;
export declare function isCredentialParsingWarnings(code: CredentialParsingError): boolean;
export declare enum GetMatchingCredentialsError {
    PresentationDefinitionParseError = "PresentationDefinitionParseError"
}
export declare enum ValidatePresentationRequirementsError {
    PresentationSubmissionParameterIsMissing = "PresentationSubmissionParameterIsMissing",
    ConstraintsAreNotSatisfied = "ConstraintsAreNotSatisfied",
    PresentationSubmissionParsingFailed = "PresentationSubmissionParsingFailed",
    FailedToParseAtLeastOnePresentation = "FailedToParseAtLeastOnePresentation",
    InvalidVpToken = "InvalidVpToken",
    CredentialParsingError = "CredentialParsingError",
    CouldNotFindAssociatedInputDescriptorBasedOnPresentationSubmission = "CouldNotFindAssociatedInputDescriptorBasedOnPresentationSubmission",
    CouldNotVerifyParsedCredentialWithInputDescriptor = "CouldNotVerifyParsedCredentialWithInputDescriptor",
    UnsupportedFormat = "UnsupportedFormat"
}
export declare enum CredentialVerificationError {
    UnknownProblem = "UnknownProblem",
    VerificationProcessNotStarted = "VerificationProcessNotStarted",// will be used when the verifier functions cannot start the verification process because of format
    InvalidDatatype = "InvalidDatatype",
    InvalidFormat = "InvalidFormat",
    MissingOpts = "MissingOpts",
    InvalidCertificateChain = "InvalidCertificateChain",
    InvalidSignature = "InvalidSignature",
    CannotResolveIssuerPublicKey = "CannotResolveIssuerPublicKey",
    CannotImportIssuerPublicKey = "CannotImportIssuerPublicKey",
    NotTrustedIssuer = "NotTrustedIssuer",
    VctRegistryNotConfigured = "VctRegistryNotConfigured",
    VctUrnNotFoundError = "VctUrnNotFoundError",
    VctSchemaError = "VctSchemaError",
    InvalidVctIntegrity = "InvalidVctIntegrity",
    ExpiredCredential = "ExpiredCredential",
    CannotImportHolderPublicKey = "CannotImportHolderPublicKey",
    CannotExtractHolderPublicKey = "CannotExtractHolderPublicKey",
    KbJwtVerificationFailedMissingParameters = "KbJwtVerificationFailedMissingParameters",
    KbJwtVerificationFailedWrongSdHash = "KbJwtVerificationFailedWrongSdHash",
    KbJwtVerificationFailedUnexpectedAudience = "KbJwtVerificationFailedUnexpectedAudience",
    KbJwtVerificationFailedUnexpectedNonce = "KbJwtVerificationFailedUnexpectedNonce",
    KbJwtVerificationFailedSignatureValidation = "KbJwtVerificationFailedSignatureValidation",
    MsoMdocMissingDeviceKeyInfo = "MsoMdocMissingDeviceKeyInfo",
    MsoMdocInvalidDeviceSignature = "MsoMdocInvalidDeviceSignature"
}
export declare enum PublicKeyResolutionError {
    CannotResolvePublicKey = "CannotResolvePublicKey"
}
export declare enum CredentialRenderingError {
    IntegrityCheckFailed = "IntegrityCheckFailed",
    CouldNotFetchSvg = "CouldNotFetchSvg"
}
//# sourceMappingURL=error.d.ts.map