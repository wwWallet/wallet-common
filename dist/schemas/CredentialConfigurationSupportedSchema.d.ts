import { z } from 'zod';
import { VerifiableCredentialFormat } from '../types';
export declare const CredentialConfigurationSupportedSchema: z.ZodUnion<[z.ZodUnion<[z.ZodObject<z.objectUtil.extendShape<{
    display: z.ZodOptional<z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        description: z.ZodOptional<z.ZodString>;
        background_color: z.ZodOptional<z.ZodString>;
        text_color: z.ZodOptional<z.ZodString>;
        alt_text: z.ZodOptional<z.ZodString>;
        background_image: z.ZodOptional<z.ZodObject<{
            uri: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            uri: string;
        }, {
            uri: string;
        }>>;
        locale: z.ZodOptional<z.ZodString>;
        logo: z.ZodOptional<z.ZodObject<{
            uri: z.ZodString;
            alt_text: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            uri: string;
            alt_text?: string | undefined;
        }, {
            uri: string;
            alt_text?: string | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }, {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }>, "many">>;
    scope: z.ZodString;
    cryptographic_binding_methods_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    credential_signing_alg_values_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    proof_types_supported: z.ZodOptional<z.ZodObject<{
        jwt: z.ZodOptional<z.ZodObject<{
            proof_signing_alg_values_supported: z.ZodArray<z.ZodString, "many">;
        }, "strip", z.ZodTypeAny, {
            proof_signing_alg_values_supported: string[];
        }, {
            proof_signing_alg_values_supported: string[];
        }>>;
        attestation: z.ZodOptional<z.ZodObject<{
            proof_signing_alg_values_supported: z.ZodArray<z.ZodString, "many">;
            key_attestations_required: z.ZodObject<{
                key_storage: z.ZodOptional<z.ZodEnum<["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]>>;
                user_authentication: z.ZodOptional<z.ZodEnum<["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]>>;
            }, "strip", z.ZodTypeAny, {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            }, {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            }>;
        }, "strip", z.ZodTypeAny, {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        }, {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        }>>;
    }, "strip", z.ZodTypeAny, {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    }, {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    }>>;
}, {
    format: z.ZodUnion<[z.ZodLiteral<VerifiableCredentialFormat.VC_SDJWT>, z.ZodLiteral<VerifiableCredentialFormat.DC_SDJWT>]>;
    vct: z.ZodString;
}>, "strip", z.ZodTypeAny, {
    vct: string;
    scope: string;
    format: VerifiableCredentialFormat.VC_SDJWT | VerifiableCredentialFormat.DC_SDJWT;
    display?: {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }[] | undefined;
    cryptographic_binding_methods_supported?: string[] | undefined;
    credential_signing_alg_values_supported?: string[] | undefined;
    proof_types_supported?: {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    } | undefined;
}, {
    vct: string;
    scope: string;
    format: VerifiableCredentialFormat.VC_SDJWT | VerifiableCredentialFormat.DC_SDJWT;
    display?: {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }[] | undefined;
    cryptographic_binding_methods_supported?: string[] | undefined;
    credential_signing_alg_values_supported?: string[] | undefined;
    proof_types_supported?: {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    } | undefined;
}>, z.ZodObject<z.objectUtil.extendShape<{
    display: z.ZodOptional<z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        description: z.ZodOptional<z.ZodString>;
        background_color: z.ZodOptional<z.ZodString>;
        text_color: z.ZodOptional<z.ZodString>;
        alt_text: z.ZodOptional<z.ZodString>;
        background_image: z.ZodOptional<z.ZodObject<{
            uri: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            uri: string;
        }, {
            uri: string;
        }>>;
        locale: z.ZodOptional<z.ZodString>;
        logo: z.ZodOptional<z.ZodObject<{
            uri: z.ZodString;
            alt_text: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            uri: string;
            alt_text?: string | undefined;
        }, {
            uri: string;
            alt_text?: string | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }, {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }>, "many">>;
    scope: z.ZodString;
    cryptographic_binding_methods_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    credential_signing_alg_values_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    proof_types_supported: z.ZodOptional<z.ZodObject<{
        jwt: z.ZodOptional<z.ZodObject<{
            proof_signing_alg_values_supported: z.ZodArray<z.ZodString, "many">;
        }, "strip", z.ZodTypeAny, {
            proof_signing_alg_values_supported: string[];
        }, {
            proof_signing_alg_values_supported: string[];
        }>>;
        attestation: z.ZodOptional<z.ZodObject<{
            proof_signing_alg_values_supported: z.ZodArray<z.ZodString, "many">;
            key_attestations_required: z.ZodObject<{
                key_storage: z.ZodOptional<z.ZodEnum<["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]>>;
                user_authentication: z.ZodOptional<z.ZodEnum<["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]>>;
            }, "strip", z.ZodTypeAny, {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            }, {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            }>;
        }, "strip", z.ZodTypeAny, {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        }, {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        }>>;
    }, "strip", z.ZodTypeAny, {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    }, {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    }>>;
}, {
    format: z.ZodLiteral<VerifiableCredentialFormat.MSO_MDOC>;
    doctype: z.ZodString;
}>, "strip", z.ZodTypeAny, {
    scope: string;
    format: VerifiableCredentialFormat.MSO_MDOC;
    doctype: string;
    display?: {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }[] | undefined;
    cryptographic_binding_methods_supported?: string[] | undefined;
    credential_signing_alg_values_supported?: string[] | undefined;
    proof_types_supported?: {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    } | undefined;
}, {
    scope: string;
    format: VerifiableCredentialFormat.MSO_MDOC;
    doctype: string;
    display?: {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }[] | undefined;
    cryptographic_binding_methods_supported?: string[] | undefined;
    credential_signing_alg_values_supported?: string[] | undefined;
    proof_types_supported?: {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    } | undefined;
}>]>, z.ZodObject<z.objectUtil.extendShape<{
    display: z.ZodOptional<z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        description: z.ZodOptional<z.ZodString>;
        background_color: z.ZodOptional<z.ZodString>;
        text_color: z.ZodOptional<z.ZodString>;
        alt_text: z.ZodOptional<z.ZodString>;
        background_image: z.ZodOptional<z.ZodObject<{
            uri: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            uri: string;
        }, {
            uri: string;
        }>>;
        locale: z.ZodOptional<z.ZodString>;
        logo: z.ZodOptional<z.ZodObject<{
            uri: z.ZodString;
            alt_text: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            uri: string;
            alt_text?: string | undefined;
        }, {
            uri: string;
            alt_text?: string | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }, {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }>, "many">>;
    scope: z.ZodString;
    cryptographic_binding_methods_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    credential_signing_alg_values_supported: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    proof_types_supported: z.ZodOptional<z.ZodObject<{
        jwt: z.ZodOptional<z.ZodObject<{
            proof_signing_alg_values_supported: z.ZodArray<z.ZodString, "many">;
        }, "strip", z.ZodTypeAny, {
            proof_signing_alg_values_supported: string[];
        }, {
            proof_signing_alg_values_supported: string[];
        }>>;
        attestation: z.ZodOptional<z.ZodObject<{
            proof_signing_alg_values_supported: z.ZodArray<z.ZodString, "many">;
            key_attestations_required: z.ZodObject<{
                key_storage: z.ZodOptional<z.ZodEnum<["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]>>;
                user_authentication: z.ZodOptional<z.ZodEnum<["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]>>;
            }, "strip", z.ZodTypeAny, {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            }, {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            }>;
        }, "strip", z.ZodTypeAny, {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        }, {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        }>>;
    }, "strip", z.ZodTypeAny, {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    }, {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    }>>;
}, {
    format: z.ZodString;
}>, "strip", z.ZodTypeAny, {
    scope: string;
    format: string;
    display?: {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }[] | undefined;
    cryptographic_binding_methods_supported?: string[] | undefined;
    credential_signing_alg_values_supported?: string[] | undefined;
    proof_types_supported?: {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    } | undefined;
}, {
    scope: string;
    format: string;
    display?: {
        name: string;
        description?: string | undefined;
        background_color?: string | undefined;
        text_color?: string | undefined;
        alt_text?: string | undefined;
        background_image?: {
            uri: string;
        } | undefined;
        locale?: string | undefined;
        logo?: {
            uri: string;
            alt_text?: string | undefined;
        } | undefined;
    }[] | undefined;
    cryptographic_binding_methods_supported?: string[] | undefined;
    credential_signing_alg_values_supported?: string[] | undefined;
    proof_types_supported?: {
        jwt?: {
            proof_signing_alg_values_supported: string[];
        } | undefined;
        attestation?: {
            proof_signing_alg_values_supported: string[];
            key_attestations_required: {
                key_storage?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
                user_authentication?: "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic" | undefined;
            };
        } | undefined;
    } | undefined;
}>]>;
export type CredentialConfigurationSupported = z.infer<typeof CredentialConfigurationSupportedSchema>;
//# sourceMappingURL=CredentialConfigurationSupportedSchema.d.ts.map