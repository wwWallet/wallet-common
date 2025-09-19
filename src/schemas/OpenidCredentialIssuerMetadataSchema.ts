import z from 'zod';
import { CredentialConfigurationSupportedSchema } from './CredentialConfigurationSupportedSchema';

export const OpenidCredentialIssuerMetadataSchema = z.object({
	credential_issuer: z.string(),
	credential_endpoint: z.string(),
	nonce_endpoint: z.string().optional(),
	credential_response_encryption: z.object({
		alg_values_supported: z.array(z.string()),
		enc_values_supported: z.array(z.string()),
		encryption_required: z.boolean(),
	}).optional(),
	authorization_servers: z.array(z.string()).optional(),
	display: z.array(z.object({
		name: z.string(),
		locale: z.string(),
	})).optional(),
	batch_credential_issuance: z.object({
		batch_size: z.number(),
	}).optional(),
	deferred_credential_endpoint: z.string().optional(),
	credential_configurations_supported: z.record(CredentialConfigurationSupportedSchema),
	signed_metadata: z.string().optional(),
	mdoc_iacas_uri: z.string().optional(),
})

export type OpenidCredentialIssuerMetadata = z.infer<typeof OpenidCredentialIssuerMetadataSchema>;
