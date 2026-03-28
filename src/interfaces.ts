import { JWK } from "jose";
import { CredentialParsingError, CredentialVerificationError, PublicKeyResolutionError, CredentialRenderingError, ValidatePresentationRequirementsError } from "./error";
import { CustomResult, ParsedCredential, CredentialClaims, ParserResult, CredentialClaimPath } from "./types";
import { VctDocumentProvider } from "./core";

export interface CredentialRendering {
	renderSvgTemplate(args: {
		json: any;
		credentialImageSvgTemplate: string;
		sdJwtVcMetadataClaims: any;
		filter?: Array<CredentialClaimPath>;
	}): Promise<string | null>
}

export interface CustomCredentialSvgI {
	renderCustomSvgTemplate(args: { signedClaims: CredentialClaims, displayConfig: any }): Promise<string>;
}

export interface CredentialIssuerInfo {
	credentialIssuerIdentifier: string;
	credentialConfigurationId: string;
}

export interface ParsingEngineI {
	register(parser: CredentialParser): void;
	parse({ rawCredential, credentialIssuer }: {
		rawCredential: unknown,
		credentialIssuer?: CredentialIssuerInfo;
	}): Promise<CustomResult<ParsedCredential, CredentialParsingError>>;
}

export interface VerifyingEngineI {
	register(credentialVerifier: CredentialVerifier): void;
	verify({ rawCredential, opts }: { rawCredential: unknown, opts: { expectedNonce?: string, expectedAudience?: string, holderNonce?: string, responseUri?: string } }): Promise<CustomResult<{ holderPublicKey: JWK; }, CredentialVerificationError>>;
}

export interface PublicKeyResolverEngineI {
	register(resolver: PublicKeyResolver): void;
	resolve(args: { identifier: string }): Promise<CustomResult<{
		jwk: JWK
	}, PublicKeyResolutionError>>;
}


export interface CredentialParser {
	parse(args: {
		rawCredential: unknown;
		credentialIssuer?: CredentialIssuerInfo;
	}): Promise<ParserResult>;
}

export interface CredentialVerifier {
	verify(args: { rawCredential: unknown, opts: { expectedNonce?: string, expectedAudience?: string, holderNonce?: string, responseUri?: string } }): Promise<CustomResult<{
		holderPublicKey: JWK,
	}, CredentialVerificationError>>;
}


export interface PublicKeyResolver {
	resolve(args: { identifier: string }): Promise<CustomResult<{
		jwk: JWK
	}, PublicKeyResolutionError>>;
}

export interface HttpClient {
	get(url: string, headers?: Record<string, unknown>, options?: any): Promise<{ status: number, headers: Record<string, unknown>, data: unknown }>;
	post(url: string, body: any, headers?: Record<string, unknown>, options?: any): Promise<{ status: number, headers: Record<string, unknown>, data: unknown }>;
}




export interface Context {
	clockTolerance: number;
	lang: string;
	subtle: SubtleCrypto;
	/**
	 * Trust anchor certificates for local certificate chain validation.
	 *
	 * Each string is a Base64-encoded DER representation without line breaks
	 * or headers like -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----.
	 *
	 * @deprecated Trust evaluation is now delegated to the AuthZEN backend.
	 * This field is only used for backwards compatibility. New code should set
	 * `skipTrustValidation: true` and rely on protocol-level trust evaluation
	 * via AuthZEN (see evaluateTrust in OpenID4VP and OID4VCI flows).
	 */
	trustedCertificates?: string[];

	/**
	 * Skip local certificate chain validation during credential verification.
	 *
	 * When true, verifiers will only check cryptographic signatures without
	 * validating certificate chains against `trustedCertificates`. This is the
	 * recommended mode when trust evaluation is delegated to AuthZEN at the
	 * protocol level (before credentials are issued/presented).
	 *
	 * @default false (for backwards compatibility)
	 */
	skipTrustValidation?: boolean;

	vctResolutionEngine?: VctDocumentProvider;
}
