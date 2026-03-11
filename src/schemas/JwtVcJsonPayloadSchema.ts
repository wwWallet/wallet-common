import { z } from "zod";

export const JwtVcJsonHeaderSchema = z.object({
	alg: z.string(),
	typ: z.string().optional(),
	kid: z.string().optional(),
	x5c: z.array(z.string()).optional(),
	jwk: z.record(z.any()).optional(),
}).passthrough();

export const JwtVcJsonPayloadSchema = z.object({
	iss: z.string().optional(),
	sub: z.string().optional(),
	iat: z.number().int().optional(),
	nbf: z.number().int().optional(),
	exp: z.number().int().optional(),
	jti: z.string().optional(),
	vc: z.object({
		"@context": z.array(z.string()).optional(),
		type: z.array(z.string()),
		credentialSubject: z.record(z.any()).optional(),
	}).passthrough().optional(),
	cnf: z.object({
		jwk: z.record(z.any()).optional(),
	}).optional(),
}).passthrough();

export type JwtVcJsonHeader = z.infer<typeof JwtVcJsonHeaderSchema>;
export type JwtVcJsonPayload = z.infer<typeof JwtVcJsonPayloadSchema>;
