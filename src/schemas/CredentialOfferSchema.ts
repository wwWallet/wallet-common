import { z } from 'zod'
import { GrantsSchema } from './GrantSchema';

export const CredentialOfferSchema = z.object({
	credential_issuer: z.string(),
	credential_configuration_ids: z.array(z.string()),
	grants: GrantsSchema.optional()
});

export type CredentialOffer = z.infer<typeof CredentialOfferSchema>;
