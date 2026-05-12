import { z } from 'zod'

export enum GrantType {
	CODE = "code",
	AUTHORIZATION_CODE = "authorization_code",
	REFRESH = "refresh_token",
	PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
}

const CommonGrantSchema = z.object({
	authorization_server: z.string().optional(),
});

const AuthorizationCodeGrantSchema = CommonGrantSchema.extend({
	issuer_state: z.string().optional(),
});

const PreAuthorizedCodeGrantSchema = CommonGrantSchema.extend({
	'pre-authorized_code': z.string(),
	tx_code: z.object({
		input_mode: z.enum(['numeric', 'text']).optional().default('numeric'),
		length: z.number().int().optional(),
		description: z.string().max(300).optional(),
	}).optional(),
});

export const GrantsSchema = z.object({
	authorization_code: AuthorizationCodeGrantSchema.optional(),
	'urn:ietf:params:oauth:grant-type:pre-authorized_code': PreAuthorizedCodeGrantSchema.optional(),
}).catchall(z.record(z.string(), z.any()));

export const GrantSchema = z.union([
	z.object({
		authorization_code: AuthorizationCodeGrantSchema,
	}),
	z.object({
		'urn:ietf:params:oauth:grant-type:pre-authorized_code': PreAuthorizedCodeGrantSchema,
	}),
]);

export type Grants = z.infer<typeof GrantsSchema>
export type Grant = z.infer<typeof GrantSchema>
