"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CredentialConfigurationSupportedSchema = void 0;
const zod_1 = require("zod");
const types_1 = require("../types");
const proofTypesSupportedSchema = zod_1.z.object({
    jwt: zod_1.z.object({
        proof_signing_alg_values_supported: zod_1.z.array(zod_1.z.string())
    }).optional(),
    attestation: zod_1.z.object({
        proof_signing_alg_values_supported: zod_1.z.array(zod_1.z.string()),
        key_attestations_required: zod_1.z.object({
            key_storage: zod_1.z.enum(["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]).optional(),
            user_authentication: zod_1.z.enum(["iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"]).optional(),
        })
    }).optional(),
});
const commonSchema = zod_1.z.object({
    display: zod_1.z.array(zod_1.z.object({
        name: zod_1.z.string(),
        description: zod_1.z.string().optional(),
        background_color: zod_1.z.string().optional(),
        text_color: zod_1.z.string().optional(),
        alt_text: zod_1.z.string().optional(),
        background_image: zod_1.z.object({
            uri: zod_1.z.string()
        }).optional(),
        locale: zod_1.z.string().optional(),
        logo: zod_1.z.object({
            uri: zod_1.z.string(),
            alt_text: zod_1.z.string().optional(),
        }).optional(),
    })).optional(),
    scope: zod_1.z.string(),
    cryptographic_binding_methods_supported: zod_1.z.array(zod_1.z.string()).optional(),
    credential_signing_alg_values_supported: zod_1.z.array(zod_1.z.string()).optional(),
    proof_types_supported: proofTypesSupportedSchema.optional(),
});
const sdJwtSchema = commonSchema.extend({
    format: zod_1.z.literal(types_1.VerifiableCredentialFormat.VC_SDJWT).or(zod_1.z.literal(types_1.VerifiableCredentialFormat.DC_SDJWT)),
    vct: zod_1.z.string()
});
const msoDocSchema = commonSchema.extend({
    format: zod_1.z.literal(types_1.VerifiableCredentialFormat.MSO_MDOC),
    doctype: zod_1.z.string()
});
const otherFormatsSchema = commonSchema.extend({
    format: zod_1.z.string(),
});
exports.CredentialConfigurationSupportedSchema = sdJwtSchema.or(msoDocSchema).or(otherFormatsSchema);
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3JlZGVudGlhbENvbmZpZ3VyYXRpb25TdXBwb3J0ZWRTY2hlbWEuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvc2NoZW1hcy9DcmVkZW50aWFsQ29uZmlndXJhdGlvblN1cHBvcnRlZFNjaGVtYS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw2QkFBd0I7QUFDeEIsb0NBQXNEO0FBRXRELE1BQU0seUJBQXlCLEdBQUcsT0FBQyxDQUFDLE1BQU0sQ0FBQztJQUMxQyxHQUFHLEVBQUUsT0FBQyxDQUFDLE1BQU0sQ0FBQztRQUNiLGtDQUFrQyxFQUFFLE9BQUMsQ0FBQyxLQUFLLENBQUMsT0FBQyxDQUFDLE1BQU0sRUFBRSxDQUFDO0tBQ3ZELENBQUMsQ0FBQyxRQUFRLEVBQUU7SUFDYixXQUFXLEVBQUUsT0FBQyxDQUFDLE1BQU0sQ0FBQztRQUNyQixrQ0FBa0MsRUFBRSxPQUFDLENBQUMsS0FBSyxDQUFDLE9BQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQztRQUN2RCx5QkFBeUIsRUFBRSxPQUFDLENBQUMsTUFBTSxDQUFDO1lBQ25DLFdBQVcsRUFBRSxPQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsZ0JBQWdCLEVBQUUsb0JBQW9CLEVBQUUsMEJBQTBCLEVBQUUsaUJBQWlCLENBQUMsQ0FBQyxDQUFDLFFBQVEsRUFBRTtZQUN2SCxtQkFBbUIsRUFBRSxPQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsZ0JBQWdCLEVBQUUsb0JBQW9CLEVBQUUsMEJBQTBCLEVBQUUsaUJBQWlCLENBQUMsQ0FBQyxDQUFDLFFBQVEsRUFBRTtTQUMvSCxDQUFDO0tBQ0YsQ0FBQyxDQUFDLFFBQVEsRUFBRTtDQUNiLENBQUMsQ0FBQztBQUdILE1BQU0sWUFBWSxHQUFHLE9BQUMsQ0FBQyxNQUFNLENBQUM7SUFDN0IsT0FBTyxFQUFFLE9BQUMsQ0FBQyxLQUFLLENBQUMsT0FBQyxDQUFDLE1BQU0sQ0FBQztRQUN6QixJQUFJLEVBQUUsT0FBQyxDQUFDLE1BQU0sRUFBRTtRQUNoQixXQUFXLEVBQUUsT0FBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLFFBQVEsRUFBRTtRQUNsQyxnQkFBZ0IsRUFBRSxPQUFDLENBQUMsTUFBTSxFQUFFLENBQUMsUUFBUSxFQUFFO1FBQ3ZDLFVBQVUsRUFBRSxPQUFDLENBQUMsTUFBTSxFQUFFLENBQUMsUUFBUSxFQUFFO1FBQ2pDLFFBQVEsRUFBRSxPQUFDLENBQUMsTUFBTSxFQUFFLENBQUMsUUFBUSxFQUFFO1FBQy9CLGdCQUFnQixFQUFFLE9BQUMsQ0FBQyxNQUFNLENBQUM7WUFDMUIsR0FBRyxFQUFFLE9BQUMsQ0FBQyxNQUFNLEVBQUU7U0FDZixDQUFDLENBQUMsUUFBUSxFQUFFO1FBQ2IsTUFBTSxFQUFFLE9BQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxRQUFRLEVBQUU7UUFDN0IsSUFBSSxFQUFFLE9BQUMsQ0FBQyxNQUFNLENBQUM7WUFDZCxHQUFHLEVBQUUsT0FBQyxDQUFDLE1BQU0sRUFBRTtZQUNmLFFBQVEsRUFBRSxPQUFDLENBQUMsTUFBTSxFQUFFLENBQUMsUUFBUSxFQUFFO1NBQy9CLENBQUMsQ0FBQyxRQUFRLEVBQUU7S0FDYixDQUFDLENBQUMsQ0FBQyxRQUFRLEVBQUU7SUFDZCxLQUFLLEVBQUUsT0FBQyxDQUFDLE1BQU0sRUFBRTtJQUNqQix1Q0FBdUMsRUFBRSxPQUFDLENBQUMsS0FBSyxDQUFDLE9BQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDLFFBQVEsRUFBRTtJQUN2RSx1Q0FBdUMsRUFBRSxPQUFDLENBQUMsS0FBSyxDQUFDLE9BQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDLFFBQVEsRUFBRTtJQUN2RSxxQkFBcUIsRUFBRSx5QkFBeUIsQ0FBQyxRQUFRLEVBQUU7Q0FDM0QsQ0FBQyxDQUFDO0FBRUgsTUFBTSxXQUFXLEdBQUcsWUFBWSxDQUFDLE1BQU0sQ0FBQztJQUN2QyxNQUFNLEVBQUUsT0FBQyxDQUFDLE9BQU8sQ0FBQyxrQ0FBMEIsQ0FBQyxRQUFRLENBQUMsQ0FBQyxFQUFFLENBQUMsT0FBQyxDQUFDLE9BQU8sQ0FBQyxrQ0FBMEIsQ0FBQyxRQUFRLENBQUMsQ0FBQztJQUN6RyxHQUFHLEVBQUUsT0FBQyxDQUFDLE1BQU0sRUFBRTtDQUNmLENBQUMsQ0FBQztBQUdILE1BQU0sWUFBWSxHQUFHLFlBQVksQ0FBQyxNQUFNLENBQUM7SUFDeEMsTUFBTSxFQUFFLE9BQUMsQ0FBQyxPQUFPLENBQUMsa0NBQTBCLENBQUMsUUFBUSxDQUFDO0lBQ3RELE9BQU8sRUFBRSxPQUFDLENBQUMsTUFBTSxFQUFFO0NBQ25CLENBQUMsQ0FBQztBQUVILE1BQU0sa0JBQWtCLEdBQUcsWUFBWSxDQUFDLE1BQU0sQ0FBQztJQUM5QyxNQUFNLEVBQUUsT0FBQyxDQUFDLE1BQU0sRUFBRTtDQUNsQixDQUFDLENBQUM7QUFFVSxRQUFBLHNDQUFzQyxHQUFHLFdBQVcsQ0FBQyxFQUFFLENBQUMsWUFBWSxDQUFDLENBQUMsRUFBRSxDQUFDLGtCQUFrQixDQUFDLENBQUMifQ==