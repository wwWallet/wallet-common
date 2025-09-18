import { z } from 'zod';
import { VerifiableCredentialFormat } from '../types';

const proofTypesSupportedSchema = z.object({
	jwt: z.object({
		proof_signing_alg_values_supported: z.array(z.string())
	}).optional(),
	attestation: z.object({
		proof_signing_alg_values_supported: z.array(z.string()),
		key_attestations_required: z.object({
			key_storage: z.enum(["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]).optional(),
			user_authentication: z.enum(["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]).optional(),
		})
	}).optional(),
});

const OpenIdClaimSchema = z.object({
	path: z.array(z.string().nullable()).nonempty(),
	mandatory: z.boolean().optional(),
	display: z.array(
		z.object({
			name: z.string().optional(),
			locale: z.string().optional(),
		})
	).optional(),
});

const commonSchema = z.object({
	display: z.array(z.object({
		name: z.string(),
		description: z.string().optional(),
		background_color: z.string().optional(),
		text_color: z.string().optional(),
		alt_text: z.string().optional(),
		background_image: z.object({
			uri: z.string()
		}).optional(),
		locale: z.string().optional(),
		logo: z.object({
			uri: z.string(),
			alt_text: z.string().optional(),
		}).optional(),
	})).optional(),
	scope: z.string(),
	claims: z.array(OpenIdClaimSchema).optional(),
	cryptographic_binding_methods_supported: z.array(z.string()).optional(),
	credential_signing_alg_values_supported: z.array(z.string()).optional(),
	proof_types_supported: proofTypesSupportedSchema.optional(),
	disclosure_policy: z.object({
		policy: z.literal("attestationBased").or(z.literal("allowList")).or(z.literal("rootOfTrust")).or(z.literal("none")),
		values: z.array(z.any()),
		url: z.string().url()
	}).optional()
});

const sdJwtSchema = commonSchema.extend({
	format: z.literal(VerifiableCredentialFormat.VC_SDJWT).or(z.literal(VerifiableCredentialFormat.DC_SDJWT)),
	vct: z.string()
});


const msoDocSchema = commonSchema.extend({
	format: z.literal(VerifiableCredentialFormat.MSO_MDOC),
	doctype: z.string()
});

const otherFormatsSchema = commonSchema.extend({
	format: z.string(),
});

export const CredentialConfigurationSupportedSchema = sdJwtSchema.or(msoDocSchema).or(otherFormatsSchema);

export type CredentialConfigurationSupported = z.infer<typeof CredentialConfigurationSupportedSchema>;

export type OpenIdClaim = z.infer<typeof OpenIdClaimSchema>;
