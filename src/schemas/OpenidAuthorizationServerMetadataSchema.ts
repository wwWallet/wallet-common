import { z } from 'zod';

export const OpenidAuthorizationServerMetadataSchema = z.object({
	issuer: z.string(),
	authorization_endpoint: z.string(),
	token_endpoint: z.string(),
	pushed_authorization_request_endpoint: z.string().optional(),
	authorization_challenge_endpoint: z.string().optional(),
	require_pushed_authorization_requests: z.boolean().optional(),
	token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
	token_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
	response_types_supported: z.array(z.string()).optional(),
	code_challenge_methods_supported: z.array(z.string()).optional(),
	dpop_signing_alg_values_supported: z.array(z.string()).optional(),
	scopes_supported: z.array(z.string()).optional(),
	grant_types_supported: z.array(z.string()).optional(),
	jwks_uri: z.string(),
});

export type OpenidAuthorizationServerMetadata = z.infer<typeof OpenidAuthorizationServerMetadataSchema>;
