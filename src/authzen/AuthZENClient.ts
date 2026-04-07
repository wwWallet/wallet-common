/**
 * AuthZEN client for trust evaluation via the wallet backend proxy.
 *
 * This client provides an interface for the frontend to make trust decisions
 * by calling the wallet backend's /v1/evaluate endpoint, which proxies requests
 * to the configured AuthZEN PDP (Policy Decision Point).
 *
 * @example
 * ```typescript
 * const client = AuthZENClient({
 *   httpClient: defaultHttpClient,
 *   baseUrl: 'https://wallet-backend.example.com',
 *   getAuthToken: () => authService.getToken(),
 *   tenantId: 'default',
 * });
 *
 * // Evaluate a verifier's trust status
 * const result = await client.evaluateVerifier({
 *   clientId: 'did:web:verifier.example.com',
 *   keyMaterial: { type: 'jwk', key: verifierJwk },
 * });
 *
 * if (result.ok && result.value.decision) {
 *   // Verifier is trusted
 * }
 * ```
 */

import { HttpClient } from '../interfaces';
import { Result, ok, err } from '../core/Result';
import {
	AuthZENEvaluationRequest,
	AuthZENEvaluationResponse,
	AuthZENResolveRequest,
	AuthZENErrorCode,
	AuthZENError,
	TrustStatus,
	TrustInfo,
} from './types';

/**
 * Configuration for the AuthZEN client.
 */
export interface AuthZENClientConfig {
	/**
	 * HTTP client for making requests.
	 */
	httpClient: HttpClient;

	/**
	 * Base URL of the wallet backend (e.g., "https://wallet-backend.example.com").
	 */
	baseUrl: string;

	/**
	 * Function to retrieve the current auth token (JWT).
	 */
	getAuthToken: () => string | Promise<string>;

	/**
	 * Tenant ID for the X-Tenant-ID header.
	 */
	tenantId: string;

	/**
	 * Request timeout in milliseconds (default: 30000).
	 */
	timeout?: number;
}

/**
 * Key material for trust evaluation.
 */
export interface KeyMaterial {
	/**
	 * Type of key material.
	 */
	type: 'jwk' | 'x5c' | 'x509_san_dns' | 'kid';

	/**
	 * Key data. For JWK, this is the JWK object.
	 * For x5c, this is an array of base64-encoded certificates.
	 * For kid, this is the key ID string (requires resolution).
	 */
	key: unknown | unknown[];
}

/**
 * Options for evaluating a verifier.
 */
export interface EvaluateVerifierOptions {
	/**
	 * The client_id of the verifier (may include scheme prefix).
	 */
	clientId: string;

	/**
	 * Key material extracted from the request JWT.
	 */
	keyMaterial: KeyMaterial;

	/**
	 * Additional context for policy evaluation.
	 */
	context?: Record<string, unknown>;
}

/**
 * Options for evaluating an issuer.
 */
export interface EvaluateIssuerOptions {
	/**
	 * The issuer identifier (typically the `iss` claim).
	 */
	issuerId: string;

	/**
	 * Key material from the issuer metadata or credential JWT.
	 */
	keyMaterial: KeyMaterial;

	/**
	 * Additional context for policy evaluation.
	 */
	context?: Record<string, unknown>;
}

/**
 * AuthZEN client interface.
 */
export interface IAuthZENClient {
	/**
	 * Send a raw AuthZEN evaluation request.
	 */
	evaluate(request: AuthZENEvaluationRequest): Promise<Result<AuthZENEvaluationResponse, AuthZENError>>;

	/**
	 * Resolve metadata for a subject (DID document, entity config, etc.).
	 */
	resolve(subjectId: string): Promise<Result<AuthZENEvaluationResponse, AuthZENError>>;

	/**
	 * Evaluate a verifier's trust status.
	 */
	evaluateVerifier(options: EvaluateVerifierOptions): Promise<Result<TrustInfo, AuthZENError>>;

	/**
	 * Evaluate an issuer's trust status.
	 */
	evaluateIssuer(options: EvaluateIssuerOptions): Promise<Result<TrustInfo, AuthZENError>>;
}

/**
 * Creates an AuthZEN client for trust evaluation.
 */
export function AuthZENClient(config: AuthZENClientConfig): IAuthZENClient {
	const { httpClient, baseUrl, getAuthToken, tenantId, timeout = 30000 } = config;

	// Normalize base URL (remove trailing slash)
	const normalizedBaseUrl = baseUrl.replace(/\/$/, '');

	/**
	 * Build request headers with auth token.
	 */
	async function buildHeaders(): Promise<Record<string, string>> {
		const token = await Promise.resolve(getAuthToken());
		return {
			'Authorization': `Bearer ${token}`,
			'X-Tenant-ID': tenantId,
			'Content-Type': 'application/json',
		};
	}

	/**
	 * Parse error response.
	 */
	function parseError(status: number, data: unknown): AuthZENError {
		if (typeof data === 'object' && data !== null) {
			const errorData = data as Record<string, unknown>;
			return {
				error: (errorData.error as string) || mapStatusToError(status),
				details: (errorData.details as string) || (errorData.message as string),
			};
		}
		return {
			error: mapStatusToError(status),
			details: 'Unknown error',
		};
	}

	/**
	 * Map HTTP status to error code.
	 */
	function mapStatusToError(status: number): AuthZENErrorCode {
		switch (status) {
			case 400:
				return AuthZENErrorCode.INVALID_REQUEST;
			case 401:
				return AuthZENErrorCode.UNAUTHORIZED;
			case 403:
				return AuthZENErrorCode.FORBIDDEN;
			case 503:
				return AuthZENErrorCode.NOT_CONFIGURED;
			case 502:
				return AuthZENErrorCode.PDP_ERROR;
			default:
				return AuthZENErrorCode.NETWORK_ERROR;
		}
	}

	/**
	 * Convert evaluation response to TrustInfo.
	 */
	function toTrustInfo(response: AuthZENEvaluationResponse): TrustInfo {
		const info: TrustInfo = {
			status: response.decision ? TrustStatus.TRUSTED : TrustStatus.UNTRUSTED,
			metadata: response.context?.trust_metadata,
		};

		// Try to extract name from metadata
		const metadata = response.context?.trust_metadata;
		if (metadata && typeof metadata === 'object') {
			const meta = metadata as Record<string, unknown>;

			// DID Document name
			if (meta.name && typeof meta.name === 'string') {
				info.name = meta.name;
			}

			// OIDF Entity Statement organization name
			if (meta.metadata && typeof meta.metadata === 'object') {
				const entityMeta = meta.metadata as Record<string, unknown>;
				const orgInfo = entityMeta.openid_credential_issuer || entityMeta.openid_relying_party || entityMeta.federation_entity;
				if (orgInfo && typeof orgInfo === 'object') {
					const org = orgInfo as Record<string, unknown>;
					if (org.organization_name && typeof org.organization_name === 'string') {
						info.name = org.organization_name;
					}
					if (org.logo_uri && typeof org.logo_uri === 'string') {
						info.logo = org.logo_uri;
					}
				}
			}
		}

		return info;
	}

	return {
		async evaluate(request: AuthZENEvaluationRequest): Promise<Result<AuthZENEvaluationResponse, AuthZENError>> {
			try {
				const headers = await buildHeaders();
				const response = await httpClient.post(
					`${normalizedBaseUrl}/v1/evaluate`,
					request,
					headers,
					{ timeout }
				);

				if (response.status === 200) {
					return ok(response.data as AuthZENEvaluationResponse);
				}

				return err(parseError(response.status, response.data));
			} catch (error) {
				return err({
					error: AuthZENErrorCode.NETWORK_ERROR,
					details: error instanceof Error ? error.message : 'Network error',
				});
			}
		},

		async resolve(subjectId: string): Promise<Result<AuthZENEvaluationResponse, AuthZENError>> {
			try {
				const headers = await buildHeaders();
				const request: AuthZENResolveRequest = { subject_id: subjectId };
				const response = await httpClient.post(
					`${normalizedBaseUrl}/v1/resolve`,
					request,
					headers,
					{ timeout }
				);

				if (response.status === 200) {
					return ok(response.data as AuthZENEvaluationResponse);
				}

				return err(parseError(response.status, response.data));
			} catch (error) {
				return err({
					error: AuthZENErrorCode.NETWORK_ERROR,
					details: error instanceof Error ? error.message : 'Network error',
				});
			}
		},

		async evaluateVerifier(options: EvaluateVerifierOptions): Promise<Result<TrustInfo, AuthZENError>> {
			const request: AuthZENEvaluationRequest = {
				subject: {
					type: 'key',
					id: options.clientId,
				},
				resource: {
					type: options.keyMaterial.type,
					id: options.clientId,
					key: Array.isArray(options.keyMaterial.key)
						? options.keyMaterial.key
						: [options.keyMaterial.key],
				},
				action: {
					name: 'credential-verifier',
				},
				context: options.context,
			};

			const result = await this.evaluate(request);
			if (!result.ok) {
				return err(result.error);
			}

			return ok(toTrustInfo(result.value));
		},

		async evaluateIssuer(options: EvaluateIssuerOptions): Promise<Result<TrustInfo, AuthZENError>> {
			const request: AuthZENEvaluationRequest = {
				subject: {
					type: 'key',
					id: options.issuerId,
				},
				resource: {
					type: options.keyMaterial.type,
					id: options.issuerId,
					key: Array.isArray(options.keyMaterial.key)
						? options.keyMaterial.key
						: [options.keyMaterial.key],
				},
				action: {
					name: 'credential-issuer',
				},
				context: options.context,
			};

			const result = await this.evaluate(request);
			if (!result.ok) {
				return err(result.error);
			}

			return ok(toTrustInfo(result.value));
		},
	};
}
