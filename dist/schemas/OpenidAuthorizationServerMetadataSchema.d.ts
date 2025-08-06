import { z } from 'zod';
export declare const OpenidAuthorizationServerMetadataSchema: z.ZodObject<{
    issuer: z.ZodString;
    authorization_endpoint: z.ZodString;
    token_endpoint: z.ZodString;
    pushed_authorization_request_endpoint: z.ZodOptional<z.ZodString>;
    authorization_challenge_endpoint: z.ZodOptional<z.ZodString>;
    require_pushed_authorization_requests: z.ZodOptional<z.ZodBoolean>;
    token_endpoint_auth_methods_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    token_endpoint_auth_signing_alg_values_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    response_types_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    code_challenge_methods_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    dpop_signing_alg_values_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    scopes_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    grant_types_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    jwks_uri: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    pushed_authorization_request_endpoint?: string | undefined;
    authorization_challenge_endpoint?: string | undefined;
    require_pushed_authorization_requests?: boolean | undefined;
    token_endpoint_auth_methods_supported?: string[] | undefined;
    token_endpoint_auth_signing_alg_values_supported?: string[] | undefined;
    response_types_supported?: string[] | undefined;
    code_challenge_methods_supported?: string[] | undefined;
    dpop_signing_alg_values_supported?: string[] | undefined;
    scopes_supported?: string[] | undefined;
    grant_types_supported?: string[] | undefined;
    jwks_uri?: string | undefined;
}, {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    pushed_authorization_request_endpoint?: string | undefined;
    authorization_challenge_endpoint?: string | undefined;
    require_pushed_authorization_requests?: boolean | undefined;
    token_endpoint_auth_methods_supported?: string[] | undefined;
    token_endpoint_auth_signing_alg_values_supported?: string[] | undefined;
    response_types_supported?: string[] | undefined;
    code_challenge_methods_supported?: string[] | undefined;
    dpop_signing_alg_values_supported?: string[] | undefined;
    scopes_supported?: string[] | undefined;
    grant_types_supported?: string[] | undefined;
    jwks_uri?: string | undefined;
}>;
export type OpenidAuthorizationServerMetadata = z.infer<typeof OpenidAuthorizationServerMetadataSchema>;
//# sourceMappingURL=OpenidAuthorizationServerMetadataSchema.d.ts.map