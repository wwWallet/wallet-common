import { describe, it, expect, vi } from 'vitest';
import { AuthZENClient, AuthZENClientConfig, KeyMaterial } from './AuthZENClient';
import {
	AuthZENErrorCode,
	TrustStatus,
	AuthZENEvaluationResponse,
} from './types';
import { HttpClient, HttpResponse } from '../interfaces';

/**
 * Mock HTTP client for testing.
 */
function createMockHttpClient(responses: Map<string, HttpResponse>): HttpClient {
	return {
		get: vi.fn().mockImplementation(async (url: string) => {
			const response = responses.get(url);
			if (response) return response;
			return { status: 404, data: { error: 'not_found' } };
		}),
		post: vi.fn().mockImplementation(async (url: string) => {
			const response = responses.get(url);
			if (response) return response;
			return { status: 404, data: { error: 'not_found' } };
		}),
	};
}

describe('AuthZENClient', () => {
	const baseUrl = 'https://wallet-backend.example.com';
	const tenantId = 'test-tenant';
	const authToken = 'test-token';

	function createClient(httpClient: HttpClient): ReturnType<typeof AuthZENClient> {
		const config: AuthZENClientConfig = {
			httpClient,
			baseUrl,
			getAuthToken: () => authToken,
			tenantId,
		};
		return AuthZENClient(config);
	}

	describe('evaluate', () => {
		it('should return successful evaluation response', async () => {
			const expectedResponse: AuthZENEvaluationResponse = {
				decision: true,
				context: {
					resolved: true,
					trust_metadata: {
						name: 'Test Verifier',
					},
				},
			};

			const responses = new Map<string, HttpResponse>([
				[`${baseUrl}/v1/evaluate`, { status: 200, data: expectedResponse }],
			]);

			const client = createClient(createMockHttpClient(responses));

			const result = await client.evaluate({
				subject: { type: 'key', id: 'did:web:example.com' },
				resource: { type: 'jwk', id: 'did:web:example.com' },
				action: { name: 'credential-verifier' },
			});

			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value.decision).toBe(true);
				expect(result.value.context?.resolved).toBe(true);
			}
		});

		it('should handle unauthorized response', async () => {
			const responses = new Map<string, HttpResponse>([
				[`${baseUrl}/v1/evaluate`, { status: 401, data: { error: 'unauthorized' } }],
			]);

			const client = createClient(createMockHttpClient(responses));

			const result = await client.evaluate({
				subject: { type: 'key', id: 'test-id' },
				resource: { type: 'jwk', id: 'test-id' },
				action: { name: 'test' },
			});

			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.error).toBe(AuthZENErrorCode.UNAUTHORIZED);
			}
		});

		it('should handle network errors', async () => {
			const httpClient: HttpClient = {
				get: vi.fn().mockRejectedValue(new Error('Network error')),
				post: vi.fn().mockRejectedValue(new Error('Network error')),
			};

			const client = createClient(httpClient);

			const result = await client.evaluate({
				subject: { type: 'key', id: 'test-id' },
				resource: { type: 'jwk', id: 'test-id' },
				action: { name: 'test' },
			});

			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.error).toBe(AuthZENErrorCode.NETWORK_ERROR);
				expect(result.error.details).toBe('Network error');
			}
		});
	});

	describe('resolve', () => {
		it('should resolve subject metadata', async () => {
			const expectedResponse: AuthZENEvaluationResponse = {
				decision: true,
				context: {
					resolved: true,
					trust_metadata: {
						type: 'did_document',
						document: { id: 'did:web:example.com' },
					},
				},
			};

			const responses = new Map<string, HttpResponse>([
				[`${baseUrl}/v1/resolve`, { status: 200, data: expectedResponse }],
			]);

			const client = createClient(createMockHttpClient(responses));

			const result = await client.resolve('did:web:example.com');

			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value.context?.trust_metadata?.type).toBe('did_document');
			}
		});
	});

	describe('evaluateVerifier', () => {
		it('should evaluate verifier and return trust info', async () => {
			const expectedResponse: AuthZENEvaluationResponse = {
				decision: true,
				context: {
					resolved: true,
					trust_metadata: {
						metadata: {
							openid_relying_party: {
								organization_name: 'Acme Corp',
								logo_uri: 'https://acme.com/logo.png',
							},
						},
					},
				},
			};

			const responses = new Map<string, HttpResponse>([
				[`${baseUrl}/v1/evaluate`, { status: 200, data: expectedResponse }],
			]);

			const client = createClient(createMockHttpClient(responses));

			const keyMaterial: KeyMaterial = {
				type: 'jwk',
				key: { kty: 'EC', crv: 'P-256', x: 'test', y: 'test' },
			};

			const result = await client.evaluateVerifier({
				clientId: 'did:web:verifier.example.com',
				keyMaterial,
			});

			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value.status).toBe(TrustStatus.TRUSTED);
				expect(result.value.name).toBe('Acme Corp');
				expect(result.value.logo).toBe('https://acme.com/logo.png');
			}
		});

		it('should return UNTRUSTED for denied decision', async () => {
			const expectedResponse: AuthZENEvaluationResponse = {
				decision: false,
				context: {
					resolved: true,
				},
			};

			const responses = new Map<string, HttpResponse>([
				[`${baseUrl}/v1/evaluate`, { status: 200, data: expectedResponse }],
			]);

			const client = createClient(createMockHttpClient(responses));

			const result = await client.evaluateVerifier({
				clientId: 'https://unknown.verifier.com',
				keyMaterial: { type: 'jwk', key: {} },
			});

			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value.status).toBe(TrustStatus.UNTRUSTED);
			}
		});
	});

	describe('evaluateIssuer', () => {
		it('should evaluate issuer with credential-issuer action', async () => {
			const expectedResponse: AuthZENEvaluationResponse = {
				decision: true,
				context: {
					resolved: true,
					trust_metadata: {
						metadata: {
							openid_credential_issuer: {
								organization_name: 'Government Issuer',
							},
						},
					},
				},
			};

			const responses = new Map<string, HttpResponse>([
				[`${baseUrl}/v1/evaluate`, { status: 200, data: expectedResponse }],
			]);

			const client = createClient(createMockHttpClient(responses));

			const result = await client.evaluateIssuer({
				issuerId: 'did:web:issuer.gov.example',
				keyMaterial: {
					type: 'x5c',
					key: ['base64-cert-1', 'base64-cert-2'],
				},
			});

			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value.status).toBe(TrustStatus.TRUSTED);
				expect(result.value.name).toBe('Government Issuer');
			}
		});
	});

	describe('configuration', () => {
		it('should normalize base URL with trailing slash', async () => {
			const responses = new Map<string, HttpResponse>([
				['https://example.com/v1/evaluate', { status: 200, data: { decision: true } }],
			]);

			const mockHttpClient = createMockHttpClient(responses);

			const config: AuthZENClientConfig = {
				httpClient: mockHttpClient,
				baseUrl: 'https://example.com/',
				getAuthToken: () => 'token',
				tenantId: 'tenant',
			};

			const client = AuthZENClient(config);

			await client.evaluate({
				subject: { type: 'key', id: 'test' },
				resource: { type: 'jwk', id: 'test' },
				action: { name: 'test' },
			});

			expect(mockHttpClient.post).toHaveBeenCalledWith(
				'https://example.com/v1/evaluate',
				expect.anything(),
				expect.objectContaining({
					'Authorization': 'Bearer token',
					'X-Tenant-ID': 'tenant',
				}),
				expect.anything()
			);
		});

		it('should support async getAuthToken', async () => {
			const responses = new Map<string, HttpResponse>([
				[`${baseUrl}/v1/evaluate`, { status: 200, data: { decision: true } }],
			]);

			const mockHttpClient = createMockHttpClient(responses);

			const config: AuthZENClientConfig = {
				httpClient: mockHttpClient,
				baseUrl,
				getAuthToken: async () => {
					await new Promise((r) => setTimeout(r, 10));
					return 'async-token';
				},
				tenantId,
			};

			const client = AuthZENClient(config);

			await client.evaluate({
				subject: { type: 'key', id: 'test' },
				resource: { type: 'jwk', id: 'test' },
				action: { name: 'test' },
			});

			expect(mockHttpClient.post).toHaveBeenCalledWith(
				expect.anything(),
				expect.anything(),
				expect.objectContaining({
					'Authorization': 'Bearer async-token',
				}),
				expect.anything()
			);
		});
	});
});
