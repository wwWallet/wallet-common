"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getIssuerMetadata = getIssuerMetadata;
const schemas_1 = require("../schemas");
const error_1 = require("../error");
async function getIssuerMetadata(httpClient, issuer, warnings, useCache = true) {
    const url = `${issuer}/.well-known/openid-credential-issuer`;
    let issuerResponse = null;
    try {
        issuerResponse = await httpClient.get(url, {}, { useCache });
    }
    catch (err) {
        warnings.push({
            code: error_1.CredentialParsingError.FailFetchIssuerMetadata,
        });
        return { metadata: null };
    }
    if (!issuerResponse || issuerResponse.status !== 200 || !issuerResponse.data) {
        warnings.push({
            code: error_1.CredentialParsingError.FailFetchIssuerMetadata,
        });
        return { metadata: null };
    }
    const parsed = schemas_1.OpenidCredentialIssuerMetadataSchema.safeParse(issuerResponse.data);
    if (!parsed.success) {
        warnings.push({
            code: error_1.CredentialParsingError.FailSchemaIssuerMetadata,
        });
        return { metadata: null };
    }
    return { metadata: parsed.data };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2V0SXNzdWVyTWV0YWRhdGEuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdXRpbHMvZ2V0SXNzdWVyTWV0YWRhdGEudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFNQSw4Q0FzQ0M7QUEzQ0Qsd0NBQWtFO0FBR2xFLG9DQUFrRDtBQUUzQyxLQUFLLFVBQVUsaUJBQWlCLENBQ3RDLFVBQXNCLEVBQ3RCLE1BQWMsRUFDZCxRQUEyQixFQUMzQixXQUFvQixJQUFJO0lBSXhCLE1BQU0sR0FBRyxHQUFHLEdBQUcsTUFBTSx1Q0FBdUMsQ0FBQztJQUU3RCxJQUFJLGNBQWMsR0FBRyxJQUFJLENBQUM7SUFFMUIsSUFBSSxDQUFDO1FBQ0osY0FBYyxHQUFHLE1BQU0sVUFBVSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsRUFBRSxFQUFFLEVBQUUsUUFBUSxFQUFFLENBQUMsQ0FBQztJQUM5RCxDQUFDO0lBQUMsT0FBTyxHQUFHLEVBQUUsQ0FBQztRQUNkLFFBQVEsQ0FBQyxJQUFJLENBQUM7WUFDYixJQUFJLEVBQUUsOEJBQXNCLENBQUMsdUJBQXVCO1NBQ3BELENBQUMsQ0FBQztRQUNILE9BQU8sRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7SUFDM0IsQ0FBQztJQUVELElBQUksQ0FBQyxjQUFjLElBQUksY0FBYyxDQUFDLE1BQU0sS0FBSyxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMsSUFBSSxFQUFFLENBQUM7UUFDOUUsUUFBUSxDQUFDLElBQUksQ0FBQztZQUNiLElBQUksRUFBRSw4QkFBc0IsQ0FBQyx1QkFBdUI7U0FDcEQsQ0FBQyxDQUFDO1FBQ0gsT0FBTyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUMzQixDQUFDO0lBRUQsTUFBTSxNQUFNLEdBQUcsOENBQW9DLENBQUMsU0FBUyxDQUFDLGNBQWMsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUVuRixJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxDQUFDO1FBQ3JCLFFBQVEsQ0FBQyxJQUFJLENBQUM7WUFDYixJQUFJLEVBQUUsOEJBQXNCLENBQUMsd0JBQXdCO1NBQ3JELENBQUMsQ0FBQztRQUNILE9BQU8sRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7SUFDM0IsQ0FBQztJQUVELE9BQU8sRUFBRSxRQUFRLEVBQUUsTUFBTSxDQUFDLElBQUksRUFBRSxDQUFDO0FBQ2xDLENBQUMifQ==