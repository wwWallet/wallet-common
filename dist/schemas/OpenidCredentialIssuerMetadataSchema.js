"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpenidCredentialIssuerMetadataSchema = void 0;
const zod_1 = __importDefault(require("zod"));
const CredentialConfigurationSupportedSchema_1 = require("./CredentialConfigurationSupportedSchema");
exports.OpenidCredentialIssuerMetadataSchema = zod_1.default.object({
    credential_issuer: zod_1.default.string(),
    credential_endpoint: zod_1.default.string(),
    nonce_endpoint: zod_1.default.string().optional(),
    credential_response_encryption: zod_1.default.object({
        alg_values_supported: zod_1.default.array(zod_1.default.string()),
        enc_values_supported: zod_1.default.array(zod_1.default.string()),
        encryption_required: zod_1.default.boolean(),
    }).optional(),
    authorization_servers: zod_1.default.array(zod_1.default.string()).optional(),
    display: zod_1.default.array(zod_1.default.object({
        name: zod_1.default.string(),
        locale: zod_1.default.string(),
    })).optional(),
    batch_credential_issuance: zod_1.default.object({
        batch_size: zod_1.default.number(),
    }).optional(),
    credential_configurations_supported: zod_1.default.record(CredentialConfigurationSupportedSchema_1.CredentialConfigurationSupportedSchema),
    signed_metadata: zod_1.default.string().optional(),
    mdoc_iacas_uri: zod_1.default.string().optional(),
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiT3BlbmlkQ3JlZGVudGlhbElzc3Vlck1ldGFkYXRhU2NoZW1hLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3NjaGVtYXMvT3BlbmlkQ3JlZGVudGlhbElzc3Vlck1ldGFkYXRhU2NoZW1hLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBLDhDQUFvQjtBQUNwQixxR0FBa0c7QUFFckYsUUFBQSxvQ0FBb0MsR0FBRyxhQUFDLENBQUMsTUFBTSxDQUFDO0lBQzVELGlCQUFpQixFQUFFLGFBQUMsQ0FBQyxNQUFNLEVBQUU7SUFDN0IsbUJBQW1CLEVBQUUsYUFBQyxDQUFDLE1BQU0sRUFBRTtJQUMvQixjQUFjLEVBQUUsYUFBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLFFBQVEsRUFBRTtJQUNyQyw4QkFBOEIsRUFBRSxhQUFDLENBQUMsTUFBTSxDQUFDO1FBQ3hDLG9CQUFvQixFQUFFLGFBQUMsQ0FBQyxLQUFLLENBQUMsYUFBQyxDQUFDLE1BQU0sRUFBRSxDQUFDO1FBQ3pDLG9CQUFvQixFQUFFLGFBQUMsQ0FBQyxLQUFLLENBQUMsYUFBQyxDQUFDLE1BQU0sRUFBRSxDQUFDO1FBQ3pDLG1CQUFtQixFQUFFLGFBQUMsQ0FBQyxPQUFPLEVBQUU7S0FDaEMsQ0FBQyxDQUFDLFFBQVEsRUFBRTtJQUNiLHFCQUFxQixFQUFFLGFBQUMsQ0FBQyxLQUFLLENBQUMsYUFBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLENBQUMsUUFBUSxFQUFFO0lBQ3JELE9BQU8sRUFBRSxhQUFDLENBQUMsS0FBSyxDQUFDLGFBQUMsQ0FBQyxNQUFNLENBQUM7UUFDekIsSUFBSSxFQUFFLGFBQUMsQ0FBQyxNQUFNLEVBQUU7UUFDaEIsTUFBTSxFQUFFLGFBQUMsQ0FBQyxNQUFNLEVBQUU7S0FDbEIsQ0FBQyxDQUFDLENBQUMsUUFBUSxFQUFFO0lBQ2QseUJBQXlCLEVBQUUsYUFBQyxDQUFDLE1BQU0sQ0FBQztRQUNuQyxVQUFVLEVBQUUsYUFBQyxDQUFDLE1BQU0sRUFBRTtLQUN0QixDQUFDLENBQUMsUUFBUSxFQUFFO0lBQ2IsbUNBQW1DLEVBQUUsYUFBQyxDQUFDLE1BQU0sQ0FBQywrRUFBc0MsQ0FBQztJQUNyRixlQUFlLEVBQUUsYUFBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLFFBQVEsRUFBRTtJQUN0QyxjQUFjLEVBQUUsYUFBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLFFBQVEsRUFBRTtDQUNyQyxDQUFDLENBQUEifQ==