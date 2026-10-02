import { describe, expect, it } from 'vitest';
import { OpenidCredentialIssuerMetadataSchema } from './OpenidCredentialIssuerMetadataSchema';

describe('OpenidCredentialIssuerMetadataSchema', () => {
	it('preserves encryption key algorithm and usage metadata', () => {
		const metadata = OpenidCredentialIssuerMetadataSchema.parse({ credential_issuer: 'https://issuer.example', credential_endpoint: 'https://issuer.example/credential', credential_request_encryption: { jwks: { keys: [{ kid: 'issuer-key', alg: 'ECDH-ES', use: 'enc', kty: 'EC' }] }, enc_values_supported: ['A256GCM'], encryption_required: true }, credential_configurations_supported: {} });
		expect(metadata.credential_request_encryption?.jwks.keys[0]).toMatchObject({ alg: 'ECDH-ES', use: 'enc' });
	});
});
