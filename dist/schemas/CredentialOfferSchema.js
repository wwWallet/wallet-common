"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CredentialOfferSchema = void 0;
const zod_1 = require("zod");
exports.CredentialOfferSchema = zod_1.z.object({
    credential_issuer: zod_1.z.string(),
    credential_configuration_ids: zod_1.z.array(zod_1.z.string()),
    grants: zod_1.z.object({
        "authorization_code": zod_1.z.object({
            "issuer_state": zod_1.z.string().optional()
        }).optional()
    })
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3JlZGVudGlhbE9mZmVyU2NoZW1hLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3NjaGVtYXMvQ3JlZGVudGlhbE9mZmVyU2NoZW1hLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLDZCQUF1QjtBQUVWLFFBQUEscUJBQXFCLEdBQUcsT0FBQyxDQUFDLE1BQU0sQ0FBQztJQUM3QyxpQkFBaUIsRUFBRSxPQUFDLENBQUMsTUFBTSxFQUFFO0lBQzdCLDRCQUE0QixFQUFFLE9BQUMsQ0FBQyxLQUFLLENBQUMsT0FBQyxDQUFDLE1BQU0sRUFBRSxDQUFDO0lBQ2pELE1BQU0sRUFBRSxPQUFDLENBQUMsTUFBTSxDQUFDO1FBQ2hCLG9CQUFvQixFQUFFLE9BQUMsQ0FBQyxNQUFNLENBQUM7WUFDOUIsY0FBYyxFQUFFLE9BQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxRQUFRLEVBQUU7U0FDckMsQ0FBQyxDQUFDLFFBQVEsRUFBRTtLQUNiLENBQUM7Q0FDRixDQUFDLENBQUEifQ==