import { assert, describe, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, JWK } from "jose";
import { JWTVCJSONVerifier } from "./JWTVCJSONVerifier";
import { Context, HttpClient, PublicKeyResolver } from "../interfaces";
import { PublicKeyResolverEngine } from "../PublicKeyResolverEngine";
import { CredentialVerificationError } from "../error";
import { PublicKeyResolutionError } from "../error";

const context: Context = {
	clockTolerance: 0,
	lang: "en-US",
	subtle: crypto.subtle,
	trustedCertificates: [],
};

const httpClient: HttpClient = {
	get: async () => ({ status: 404, headers: {}, data: {} }),
	post: async () => ({ status: 404, headers: {}, data: {} }),
};

async function buildJwtVcJson(opts?: { expOffsetSec?: number; includeHolderCnf?: boolean }): Promise<{ jwt: string; issuerPublicJwk: JWK }> {
	const issuerKeyPair = await generateKeyPair("ES256");
	const issuerPublicJwk = await exportJWK(issuerKeyPair.publicKey);
	const holderKeyPair = await generateKeyPair("ES256");
	const holderPublicJwk = await exportJWK(holderKeyPair.publicKey);

	const now = Math.floor(Date.now() / 1000);
	const jwt = await new SignJWT({
		iss: "https://issuer.example.org",
		sub: "did:example:holder",
		iat: now,
		nbf: now,
		exp: now + (opts?.expOffsetSec ?? 3600),
		vc: {
			type: ["VerifiableCredential", "PIDCredential"],
			credentialSubject: { given_name: "Ada" },
		},
		...(opts?.includeHolderCnf === false ? {} : { cnf: { jwk: holderPublicJwk } }),
	})
		.setProtectedHeader({ alg: "ES256", typ: "jwt_vc_json" })
		.sign(issuerKeyPair.privateKey);

	return { jwt, issuerPublicJwk };
}

describe("JWTVCJSONVerifier", () => {
	it("verifies valid jwt_vc_json and returns holder public key", async () => {
		const { jwt, issuerPublicJwk } = await buildJwtVcJson();
		const pkResolverEngine = PublicKeyResolverEngine();
		const resolver: PublicKeyResolver = {
			resolve: async ({ identifier }) => {
				if (identifier === "https://issuer.example.org") {
					return { success: true, value: { jwk: issuerPublicJwk } };
				}
				return { success: false, error: PublicKeyResolutionError.CouldNotResolve };
			},
		};
		pkResolverEngine.register(resolver);

		const verifier = JWTVCJSONVerifier({ context, pkResolverEngine, httpClient });
		const result = await verifier.verify({ rawCredential: jwt, opts: {} });

		assert(result.success === true);
		if (result.success) {
			assert(result.value.holderPublicKey.kty === "EC");
		}
	});

	it("fails for expired jwt_vc_json", async () => {
		const { jwt, issuerPublicJwk } = await buildJwtVcJson({ expOffsetSec: -60 });
		const pkResolverEngine = PublicKeyResolverEngine();
		pkResolverEngine.register({
			resolve: async () => ({ success: true, value: { jwk: issuerPublicJwk } }),
		});

		const verifier = JWTVCJSONVerifier({ context, pkResolverEngine, httpClient });
		const result = await verifier.verify({ rawCredential: jwt, opts: {} });

		assert(result.success === false);
		if (!result.success) {
			assert(result.error === CredentialVerificationError.ExpiredCredential);
		}
	});

	it("returns VerificationProcessNotStarted for non-jwt input", async () => {
		const pkResolverEngine = PublicKeyResolverEngine();
		const verifier = JWTVCJSONVerifier({ context, pkResolverEngine, httpClient });
		const result = await verifier.verify({ rawCredential: "not-a-jwt", opts: {} });

		assert(result.success === false);
		if (!result.success) {
			assert(result.error === CredentialVerificationError.VerificationProcessNotStarted);
		}
	});
});
