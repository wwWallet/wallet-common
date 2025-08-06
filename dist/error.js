"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CredentialRenderingError = exports.PublicKeyResolutionError = exports.CredentialVerificationError = exports.ValidatePresentationRequirementsError = exports.GetMatchingCredentialsError = exports.CredentialParsingWarnings = exports.CredentialParsingError = void 0;
exports.isCredentialParsingWarnings = isCredentialParsingWarnings;
var CredentialParsingError;
(function (CredentialParsingError) {
    CredentialParsingError["CouldNotParse"] = "CouldNotParse";
    CredentialParsingError["InvalidSdJwtVcPayload"] = "InvalidSdJwtVcPayload";
    CredentialParsingError["InvalidDatatype"] = "InvalidDatatype";
    CredentialParsingError["NotSupportedCredentialType"] = "NotSupportedCredentialType";
    CredentialParsingError["HeaderFail"] = "HeaderFail";
    CredentialParsingError["SchemaFetchFail"] = "SchemaFetchFail";
    CredentialParsingError["SchemaConflict"] = "SchemaConflict";
    CredentialParsingError["InfiniteRecursion"] = "InfiniteRecursion";
    CredentialParsingError["PayloadFail"] = "PayloadFail";
    CredentialParsingError["VctmDecodeFail"] = "VctmDecodeFail";
    CredentialParsingError["UnknownError"] = "UnknownError";
    CredentialParsingError["NotFound"] = "NotFound";
    CredentialParsingError["IntegrityMissing"] = "IntegrityMissing";
    CredentialParsingError["JwtVcIssuerMismatch"] = "JwtVcIssuerMismatch";
    CredentialParsingError["IntegrityFail"] = "IntegrityFail";
    CredentialParsingError["SchemaFail"] = "SchemaFail";
    CredentialParsingError["JwtVcIssuerFail"] = "JwtVcIssuerFail";
    CredentialParsingError["FailFetchIssuerMetadata"] = "FailFetchIssuerMetadata";
    CredentialParsingError["FailSchemaIssuerMetadata"] = "FailSchemaIssuerMetadata";
})(CredentialParsingError || (exports.CredentialParsingError = CredentialParsingError = {}));
exports.CredentialParsingWarnings = new Set([
    CredentialParsingError.NotFound,
    CredentialParsingError.IntegrityMissing,
    CredentialParsingError.JwtVcIssuerMismatch,
    CredentialParsingError.IntegrityFail,
    CredentialParsingError.SchemaFail,
    CredentialParsingError.JwtVcIssuerFail,
    CredentialParsingError.FailFetchIssuerMetadata,
    CredentialParsingError.FailSchemaIssuerMetadata,
]);
function isCredentialParsingWarnings(code) {
    return exports.CredentialParsingWarnings.has(code);
}
var GetMatchingCredentialsError;
(function (GetMatchingCredentialsError) {
    GetMatchingCredentialsError["PresentationDefinitionParseError"] = "PresentationDefinitionParseError";
})(GetMatchingCredentialsError || (exports.GetMatchingCredentialsError = GetMatchingCredentialsError = {}));
var ValidatePresentationRequirementsError;
(function (ValidatePresentationRequirementsError) {
    ValidatePresentationRequirementsError["PresentationSubmissionParameterIsMissing"] = "PresentationSubmissionParameterIsMissing";
    ValidatePresentationRequirementsError["ConstraintsAreNotSatisfied"] = "ConstraintsAreNotSatisfied";
    ValidatePresentationRequirementsError["PresentationSubmissionParsingFailed"] = "PresentationSubmissionParsingFailed";
    ValidatePresentationRequirementsError["FailedToParseAtLeastOnePresentation"] = "FailedToParseAtLeastOnePresentation";
    ValidatePresentationRequirementsError["InvalidVpToken"] = "InvalidVpToken";
    ValidatePresentationRequirementsError["CredentialParsingError"] = "CredentialParsingError";
    ValidatePresentationRequirementsError["CouldNotFindAssociatedInputDescriptorBasedOnPresentationSubmission"] = "CouldNotFindAssociatedInputDescriptorBasedOnPresentationSubmission";
    ValidatePresentationRequirementsError["CouldNotVerifyParsedCredentialWithInputDescriptor"] = "CouldNotVerifyParsedCredentialWithInputDescriptor";
    ValidatePresentationRequirementsError["UnsupportedFormat"] = "UnsupportedFormat";
})(ValidatePresentationRequirementsError || (exports.ValidatePresentationRequirementsError = ValidatePresentationRequirementsError = {}));
var CredentialVerificationError;
(function (CredentialVerificationError) {
    CredentialVerificationError["UnknownProblem"] = "UnknownProblem";
    CredentialVerificationError["VerificationProcessNotStarted"] = "VerificationProcessNotStarted";
    CredentialVerificationError["InvalidDatatype"] = "InvalidDatatype";
    CredentialVerificationError["InvalidFormat"] = "InvalidFormat";
    CredentialVerificationError["MissingOpts"] = "MissingOpts";
    CredentialVerificationError["InvalidCertificateChain"] = "InvalidCertificateChain";
    CredentialVerificationError["InvalidSignature"] = "InvalidSignature";
    CredentialVerificationError["CannotResolveIssuerPublicKey"] = "CannotResolveIssuerPublicKey";
    CredentialVerificationError["CannotImportIssuerPublicKey"] = "CannotImportIssuerPublicKey";
    CredentialVerificationError["NotTrustedIssuer"] = "NotTrustedIssuer";
    CredentialVerificationError["VctRegistryNotConfigured"] = "VctRegistryNotConfigured";
    CredentialVerificationError["VctUrnNotFoundError"] = "VctUrnNotFoundError";
    CredentialVerificationError["VctSchemaError"] = "VctSchemaError";
    CredentialVerificationError["InvalidVctIntegrity"] = "InvalidVctIntegrity";
    CredentialVerificationError["ExpiredCredential"] = "ExpiredCredential";
    CredentialVerificationError["CannotImportHolderPublicKey"] = "CannotImportHolderPublicKey";
    CredentialVerificationError["CannotExtractHolderPublicKey"] = "CannotExtractHolderPublicKey";
    // KBJWT related
    CredentialVerificationError["KbJwtVerificationFailedMissingParameters"] = "KbJwtVerificationFailedMissingParameters";
    CredentialVerificationError["KbJwtVerificationFailedWrongSdHash"] = "KbJwtVerificationFailedWrongSdHash";
    CredentialVerificationError["KbJwtVerificationFailedUnexpectedAudience"] = "KbJwtVerificationFailedUnexpectedAudience";
    CredentialVerificationError["KbJwtVerificationFailedUnexpectedNonce"] = "KbJwtVerificationFailedUnexpectedNonce";
    CredentialVerificationError["KbJwtVerificationFailedSignatureValidation"] = "KbJwtVerificationFailedSignatureValidation";
    // MSO MDOC related
    CredentialVerificationError["MsoMdocMissingDeviceKeyInfo"] = "MsoMdocMissingDeviceKeyInfo";
    CredentialVerificationError["MsoMdocInvalidDeviceSignature"] = "MsoMdocInvalidDeviceSignature";
})(CredentialVerificationError || (exports.CredentialVerificationError = CredentialVerificationError = {}));
var PublicKeyResolutionError;
(function (PublicKeyResolutionError) {
    PublicKeyResolutionError["CannotResolvePublicKey"] = "CannotResolvePublicKey";
})(PublicKeyResolutionError || (exports.PublicKeyResolutionError = PublicKeyResolutionError = {}));
var CredentialRenderingError;
(function (CredentialRenderingError) {
    CredentialRenderingError["IntegrityCheckFailed"] = "IntegrityCheckFailed";
    CredentialRenderingError["CouldNotFetchSvg"] = "CouldNotFetchSvg";
})(CredentialRenderingError || (exports.CredentialRenderingError = CredentialRenderingError = {}));
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXJyb3IuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvZXJyb3IudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBaUNBLGtFQUVDO0FBbkNELElBQVksc0JBb0JYO0FBcEJELFdBQVksc0JBQXNCO0lBQ2pDLHlEQUErQixDQUFBO0lBQy9CLHlFQUE4QyxDQUFBO0lBQzlDLDZEQUFtQyxDQUFBO0lBQ25DLG1GQUF5RCxDQUFBO0lBQ3pELG1EQUF5QixDQUFBO0lBQ3pCLDZEQUFtQyxDQUFBO0lBQ25DLDJEQUFpQyxDQUFBO0lBQ2pDLGlFQUF1QyxDQUFBO0lBQ3ZDLHFEQUEyQixDQUFBO0lBQzNCLDJEQUFpQyxDQUFBO0lBQ2pDLHVEQUE2QixDQUFBO0lBQzdCLCtDQUFxQixDQUFBO0lBQ3JCLCtEQUFxQyxDQUFBO0lBQ3JDLHFFQUEyQyxDQUFBO0lBQzNDLHlEQUErQixDQUFBO0lBQy9CLG1EQUF5QixDQUFBO0lBQ3pCLDZEQUFtQyxDQUFBO0lBQ25DLDZFQUFtRCxDQUFBO0lBQ25ELCtFQUFxRCxDQUFBO0FBQ3RELENBQUMsRUFwQlcsc0JBQXNCLHNDQUF0QixzQkFBc0IsUUFvQmpDO0FBRVksUUFBQSx5QkFBeUIsR0FBRyxJQUFJLEdBQUcsQ0FBeUI7SUFDeEUsc0JBQXNCLENBQUMsUUFBUTtJQUMvQixzQkFBc0IsQ0FBQyxnQkFBZ0I7SUFDdkMsc0JBQXNCLENBQUMsbUJBQW1CO0lBQzFDLHNCQUFzQixDQUFDLGFBQWE7SUFDcEMsc0JBQXNCLENBQUMsVUFBVTtJQUNqQyxzQkFBc0IsQ0FBQyxlQUFlO0lBQ3RDLHNCQUFzQixDQUFDLHVCQUF1QjtJQUM5QyxzQkFBc0IsQ0FBQyx3QkFBd0I7Q0FDL0MsQ0FBQyxDQUFDO0FBRUgsU0FBZ0IsMkJBQTJCLENBQUMsSUFBNEI7SUFDdkUsT0FBTyxpQ0FBeUIsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDNUMsQ0FBQztBQUVELElBQVksMkJBRVg7QUFGRCxXQUFZLDJCQUEyQjtJQUN0QyxvR0FBcUUsQ0FBQTtBQUN0RSxDQUFDLEVBRlcsMkJBQTJCLDJDQUEzQiwyQkFBMkIsUUFFdEM7QUFFRCxJQUFZLHFDQVdYO0FBWEQsV0FBWSxxQ0FBcUM7SUFDaEQsOEhBQXFGLENBQUE7SUFDckYsa0dBQXlELENBQUE7SUFDekQsb0hBQTJFLENBQUE7SUFDM0Usb0hBQTJFLENBQUE7SUFDM0UsMEVBQWlDLENBQUE7SUFDakMsMEZBQWlELENBQUE7SUFDakQsa0xBQXlJLENBQUE7SUFDekksZ0pBQXVHLENBQUE7SUFDdkcsZ0ZBQXVDLENBQUE7QUFFeEMsQ0FBQyxFQVhXLHFDQUFxQyxxREFBckMscUNBQXFDLFFBV2hEO0FBRUQsSUFBWSwyQkFrQ1g7QUFsQ0QsV0FBWSwyQkFBMkI7SUFDdEMsZ0VBQWlDLENBQUE7SUFDakMsOEZBQStELENBQUE7SUFDL0Qsa0VBQW1DLENBQUE7SUFDbkMsOERBQStCLENBQUE7SUFDL0IsMERBQTJCLENBQUE7SUFDM0Isa0ZBQW1ELENBQUE7SUFHbkQsb0VBQXFDLENBQUE7SUFDckMsNEZBQTZELENBQUE7SUFDN0QsMEZBQTJELENBQUE7SUFDM0Qsb0VBQXFDLENBQUE7SUFDckMsb0ZBQXFELENBQUE7SUFDckQsMEVBQTJDLENBQUE7SUFDM0MsZ0VBQWlDLENBQUE7SUFDakMsMEVBQTJDLENBQUE7SUFFM0Msc0VBQXVDLENBQUE7SUFFdkMsMEZBQTJELENBQUE7SUFDM0QsNEZBQTZELENBQUE7SUFFN0QsZ0JBQWdCO0lBQ2hCLG9IQUFxRixDQUFBO0lBQ3JGLHdHQUF5RSxDQUFBO0lBQ3pFLHNIQUF1RixDQUFBO0lBQ3ZGLGdIQUFpRixDQUFBO0lBQ2pGLHdIQUF5RixDQUFBO0lBR3pGLG1CQUFtQjtJQUNuQiwwRkFBMkQsQ0FBQTtJQUMzRCw4RkFBK0QsQ0FBQTtBQUNoRSxDQUFDLEVBbENXLDJCQUEyQiwyQ0FBM0IsMkJBQTJCLFFBa0N0QztBQUVELElBQVksd0JBRVg7QUFGRCxXQUFZLHdCQUF3QjtJQUNuQyw2RUFBaUQsQ0FBQTtBQUNsRCxDQUFDLEVBRlcsd0JBQXdCLHdDQUF4Qix3QkFBd0IsUUFFbkM7QUFFRCxJQUFZLHdCQUdYO0FBSEQsV0FBWSx3QkFBd0I7SUFDbkMseUVBQTZDLENBQUE7SUFDN0MsaUVBQXFDLENBQUE7QUFDdEMsQ0FBQyxFQUhXLHdCQUF3Qix3Q0FBeEIsd0JBQXdCLFFBR25DIn0=