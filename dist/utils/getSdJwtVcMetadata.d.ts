import { Context, HttpClient } from '../interfaces';
import { MetadataError, MetadataWarning } from '../types';
import { CredentialParsingError } from '../error';
export declare function validateAgainstSchema(schema: Record<string, any>, dataToValidate?: Record<string, any>): CredentialParsingError | undefined;
export declare function resolveIssuerMetadata(httpClient: any, issuerUrl: string): Promise<{
    code: CredentialParsingError;
} | undefined>;
export declare function getSdJwtVcMetadata(context: Context, httpClient: HttpClient, credential: string, parsedClaims: Record<string, unknown>, warnings?: MetadataWarning[]): Promise<{
    credentialMetadata: any;
    warnings: MetadataWarning[];
} | MetadataError>;
//# sourceMappingURL=getSdJwtVcMetadata.d.ts.map