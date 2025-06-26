import { describe, it } from 'vitest';
import { OpenidAuthorizationServerMetadataSchema } from './OpenidAuthorizationServerMetadataSchema';
import assert from 'assert';


const metadata = {
	"issuer": "https://wallet.a-sit.at/m6",
	"authorization_endpoint": "https://wallet.a-sit.at/m6/authorize",
	"pushed_authorization_request_endpoint": "https://wallet.a-sit.at/m6/par",
	"require_pushed_authorization_requests": true,
	"token_endpoint": "https://wallet.a-sit.at/m6/token",
	"token_endpoint_auth_methods_supported": [
		"attest_jwt_client_auth"
	],
	"jwks_uri": "https://example.com/jwks",
};


describe("OpenidCredentialIssuerMetadataSchemaValera", () => {
	it("should successfully parse Valera issuer's metadata", async () => {
		const res = OpenidAuthorizationServerMetadataSchema.safeParse(metadata);
		if (res.error) {
			console.dir(res.error, { depth: null });
		}
		assert(res.success === true);
	})
})
