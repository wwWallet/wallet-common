import { z } from 'zod';
export declare const CredentialOfferSchema: z.ZodObject<{
    credential_issuer: z.ZodString;
    credential_configuration_ids: z.ZodArray<z.ZodString, "many">;
    grants: z.ZodObject<{
        authorization_code: z.ZodOptional<z.ZodObject<{
            issuer_state: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            issuer_state?: string | undefined;
        }, {
            issuer_state?: string | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        authorization_code?: {
            issuer_state?: string | undefined;
        } | undefined;
    }, {
        authorization_code?: {
            issuer_state?: string | undefined;
        } | undefined;
    }>;
}, "strip", z.ZodTypeAny, {
    credential_issuer: string;
    credential_configuration_ids: string[];
    grants: {
        authorization_code?: {
            issuer_state?: string | undefined;
        } | undefined;
    };
}, {
    credential_issuer: string;
    credential_configuration_ids: string[];
    grants: {
        authorization_code?: {
            issuer_state?: string | undefined;
        } | undefined;
    };
}>;
export type CredentialOffer = z.infer<typeof CredentialOfferSchema>;
//# sourceMappingURL=CredentialOfferSchema.d.ts.map