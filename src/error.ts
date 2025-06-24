export enum CredentialParsingError {
	MissingIssuerIdentifier = "MissingIssuerIdentifier",
	CouldNotParse = "CouldNotParse",
	InvalidDatatype = "InvalidDatatype",
	NotSupportedCredentialType = "NotSupportedCredentialType",
}

export enum GetMatchingCredentialsError {
	PresentationDefinitionParseError = "PresentationDefinitionParseError"
}

export enum ValidatePresentationRequirementsError {
	PresentationSubmissionParameterIsMissing = "PresentationSubmissionParameterIsMissing",
	ConstraintsAreNotSatisfied = "ConstraintsAreNotSatisfied",
	PresentationSubmissionParsingFailed = "PresentationSubmissionParsingFailed",
	FailedToParseAtLeastOnePresentation = "FailedToParseAtLeastOnePresentation",
	InvalidVpToken = "InvalidVpToken",
	CredentialParsingError = "CredentialParsingError",
	CouldNotFindAssociatedInputDescriptorBasedOnPresentationSubmission = "CouldNotFindAssociatedInputDescriptorBasedOnPresentationSubmission",
	CouldNotVerifyParsedCredentialWithInputDescriptor = "CouldNotVerifyParsedCredentialWithInputDescriptor",
	UnsupportedFormat = "UnsupportedFormat",

}

export enum CredentialVerificationError {
	UnknownProblem = "UnknownProblem",
	VerificationProcessNotStarted = "VerificationProcessNotStarted", // will be used when the verifier functions cannot start the verification process because of format
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

	ExpiredCredential = "ExpiredCredential",

	CannotImportHolderPublicKey = "CannotImportHolderPublicKey",
	CannotExtractHolderPublicKey = "CannotExtractHolderPublicKey",

	// KBJWT related
	KbJwtVerificationFailedMissingParameters = "KbJwtVerificationFailedMissingParameters",
	KbJwtVerificationFailedWrongSdHash = "KbJwtVerificationFailedWrongSdHash",
	KbJwtVerificationFailedUnexpectedAudience = "KbJwtVerificationFailedUnexpectedAudience",
	KbJwtVerificationFailedUnexpectedNonce = "KbJwtVerificationFailedUnexpectedNonce",
	KbJwtVerificationFailedSignatureValidation = "KbJwtVerificationFailedSignatureValidation",


	// MSO MDOC related
	MsoMdocMissingDeviceKeyInfo = "MsoMdocMissingDeviceKeyInfo",
	MsoMdocInvalidDeviceSignature = "MsoMdocInvalidDeviceSignature",
}

export enum PublicKeyResolutionError {
	CannotResolvePublicKey = "CannotResolvePublicKey",
}

export enum CredentialRenderingError {
	IntegrityCheckFailed = "IntegrityCheckFailed",
	CouldNotFetchSvg = "CouldNotFetchSvg",
}

// NOTE error codes according to https://datatracker.ietf.org/doc/html/rfc6749#section-8.5 and OID4VCI and OID4VP extensions
type errorCode = 'server_error' | 'invalid_request'

type internalCode = CredentialVerificationError.VctUrnNotFoundError

type statusCode = 400

export type ErrorResponse = {
  status: statusCode
  response: {
    error: errorCode
    error_description: string
  }
}

const errorResponses: {
  [k in internalCode]: ErrorResponse
} = {
  [CredentialVerificationError.VctUrnNotFoundError]: {
    status: 400,
    response: {
      error: 'invalid_request',
      error_description: 'Credential vct could not be resolved'
    }
  }
}

export class OauthError extends Error {
  response: ErrorResponse
  name: internalCode

  constructor (name: internalCode) {
    super(name)
    this.name = name
    this.response = errorResponses[name] || {
      status: 500,
      response: {
        error: 'server_error',
        error_description: name
      }
    }
  }
}
