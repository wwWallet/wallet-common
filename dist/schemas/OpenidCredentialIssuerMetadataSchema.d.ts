import z from 'zod';
export declare const OpenidCredentialIssuerMetadataSchema: z.ZodObject<{
    credential_issuer: z.ZodString;
    credential_endpoint: z.ZodString;
    nonce_endpoint: z.ZodOptional<z.ZodString>;
    credential_response_encryption: z.ZodOptional<z.ZodObject<{
        alg_values_supported: z.ZodArray<z.ZodString, "many">;
        enc_values_supported: z.ZodArray<z.ZodString, "many">;
        encryption_required: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        alg_values_supported: string[];
        enc_values_supported: string[];
        encryption_required: boolean;
    }, {
        alg_values_supported: string[];
        enc_values_supported: string[];
        encryption_required: boolean;
    }>>;
    authorization_servers: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    display: z.ZodOptional<z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        locale: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        name: string;
        locale: string;
    }, {
        name: string;
        locale: string;
    }>, "many">>;
    batch_credential_issuance: z.ZodOptional<z.ZodObject<{
        batch_size: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        batch_size: number;
    }, {
        batch_size: number;
    }>>;
    credential_configurations_supported: z.ZodRecord<z.ZodString, z.ZodUnion<[z.ZodUnion<[z.ZodObject<z.objectUtil.extendShape<{
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
        format: z.ZodUnion<[z.ZodLiteral<import("../types").VerifiableCredentialFormat.VC_SDJWT>, z.ZodLiteral<import("../types").VerifiableCredentialFormat.DC_SDJWT>]>;
        vct: z.ZodString;
    }>, "strip", z.ZodTypeAny, {
        vct: string;
        scope: string;
        format: import("../types").VerifiableCredentialFormat.VC_SDJWT | import("../types").VerifiableCredentialFormat.DC_SDJWT;
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
        format: import("../types").VerifiableCredentialFormat.VC_SDJWT | import("../types").VerifiableCredentialFormat.DC_SDJWT;
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
        format: z.ZodLiteral<import("../types").VerifiableCredentialFormat.MSO_MDOC>;
        doctype: z.ZodString;
    }>, "strip", z.ZodTypeAny, {
        scope: string;
        format: import("../types").VerifiableCredentialFormat.MSO_MDOC;
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
        format: import("../types").VerifiableCredentialFormat.MSO_MDOC;
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
    }>]>>;
    signed_metadata: z.ZodOptional<z.ZodString>;
    mdoc_iacas_uri: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    credential_issuer: string;
    credential_endpoint: string;
    credential_configurations_supported: Record<string, {
        vct: string;
        scope: string;
        format: import("../types").VerifiableCredentialFormat.VC_SDJWT | import("../types").VerifiableCredentialFormat.DC_SDJWT;
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
    } | {
        scope: string;
        format: import("../types").VerifiableCredentialFormat.MSO_MDOC;
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
    } | {
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
    }>;
    display?: {
        name: string;
        locale: string;
    }[] | undefined;
    nonce_endpoint?: string | undefined;
    credential_response_encryption?: {
        alg_values_supported: string[];
        enc_values_supported: string[];
        encryption_required: boolean;
    } | undefined;
    authorization_servers?: string[] | undefined;
    batch_credential_issuance?: {
        batch_size: number;
    } | undefined;
    signed_metadata?: string | undefined;
    mdoc_iacas_uri?: string | undefined;
}, {
    credential_issuer: string;
    credential_endpoint: string;
    credential_configurations_supported: Record<string, {
        vct: string;
        scope: string;
        format: import("../types").VerifiableCredentialFormat.VC_SDJWT | import("../types").VerifiableCredentialFormat.DC_SDJWT;
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
    } | {
        scope: string;
        format: import("../types").VerifiableCredentialFormat.MSO_MDOC;
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
    } | {
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
    }>;
    display?: {
        name: string;
        locale: string;
    }[] | undefined;
    nonce_endpoint?: string | undefined;
    credential_response_encryption?: {
        alg_values_supported: string[];
        enc_values_supported: string[];
        encryption_required: boolean;
    } | undefined;
    authorization_servers?: string[] | undefined;
    batch_credential_issuance?: {
        batch_size: number;
    } | undefined;
    signed_metadata?: string | undefined;
    mdoc_iacas_uri?: string | undefined;
}>;
export type OpenidCredentialIssuerMetadata = z.infer<typeof OpenidCredentialIssuerMetadataSchema>;
//# sourceMappingURL=OpenidCredentialIssuerMetadataSchema.d.ts.map