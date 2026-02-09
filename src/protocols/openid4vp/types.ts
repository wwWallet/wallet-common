import type { JWK } from "jose";

export type ClaimRecord = {
	key: string;
	name: string;
	value: string;
};

export type PresentationClaims = Record<string, ClaimRecord[]>;

export type PresentationInfo = {
	[descriptor_id: string]: Array<string>;
}

export interface RPState {
	session_id: string;
	is_cross_device: boolean;
	signed_request: string;
	state: string;
	nonce: string;

	callback_endpoint: string | null;

	audience: string;
	presentation_request_id: string;

	presentation_definition: unknown | null;

	dcql_query: unknown | null;

	rp_eph_kid: string;

	rp_eph_pub: JWK;

	rp_eph_priv: JWK;

	apv_jarm_encrypted_response_header: string | null;
	apu_jarm_encrypted_response_header: string | null;

	encrypted_response: string | null;
	vp_token: string | null;

	presentation_submission: unknown | null;

	response_code: string | null;

	claims: PresentationClaims | null;

	completed: boolean | null;

	presentation_during_issuance_session: string | null;

	date_created: number;
}

export type CredentialEngineOptions = {
	clockTolerance: number;
	subtle: SubtleCrypto;
	lang: string;
	trustedCertificates: string[];
	trustedCredentialIssuerIdentifiers: string[] | undefined;
};

export type OpenID4VPOptions = {
	credentialEngineOptions: CredentialEngineOptions,
	redirectUri: string
};

export type CredentialIssuerMetadata = {
	mdoc_iacas_uri?: string;
};

export type IacasResponse = {
	iacas?: Array<{ certificate?: string }>;
};

export enum ResponseMode {
	DIRECT_POST = "direct_post",
	DIRECT_POST_JWT = "direct_post.jwt",
	DC_API = "dc_api",
	DC_API_JWT = "dc_api.jwt",
}

export type OpenID4VPClientMetadata = {
	jwks?: { keys: any[] };
	jwks_uri?: string;
	authorization_encrypted_response_alg?: string;
	authorization_encrypted_response_enc?: string;
	vp_formats: any;
};

export type OpenID4VPRelyingPartyState = {
	nonce: string;
	response_uri: string;
	client_id: string;
	state: string;
	client_metadata: OpenID4VPClientMetadata;
	response_mode: ResponseMode;
	transaction_data: string[];
	dcql_query: Record<string, unknown>;
};

export type OpenID4VPServerMessages = {
	purposeNotSpecified: string;
	allClaimsRequested: string;
};

export type OpenID4VPServerLastUsedNonceStore = {
	get(): string | null;
	set(nonce: string): void;
};

export type OpenID4VPServerRequestVerifier = (params: {
	request_uri: string;
	response_uri: string;
	parsedHeader: Record<string, unknown>;
}) => Promise<void>;

export type TransactionDataResponseParams = {
	transaction_data_hashes: string[];
	transaction_data_hashes_alg: string[];
};

export type TransactionDataResponseGenerator = {
	generateTransactionDataResponse(transaction_data: string[]): Promise<[TransactionDataResponseParams | null, Error | null]>;
};

export type TransactionDataResponseGeneratorParams = {
	descriptor_id: string;
	dcql_query: Record<string, unknown>;
};
