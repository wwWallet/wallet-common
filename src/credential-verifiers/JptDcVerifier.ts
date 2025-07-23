import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { JWK } from "jose";
import { IssuedJpt, JptClaims, parseJpt, PresentedJpt } from "../jpt";
import { importIssuerPublicJwk } from "../jwp";
import * as jwp from "../jwp";
import { Result } from "../types";

export function JptDcVerifier(args: {
	context: Context,
	pkResolverEngine: PublicKeyResolverEngineI,
	httpClient: HttpClient,
	issuerPublicKeys: { kty: 'EC', crv: 'BLS12381G2' }[],
}): CredentialVerifier {
	return {
		async verify({ rawCredential, opts }) {
			if (typeof rawCredential !== 'string') {
				return {
					success: false,
					error: CredentialVerificationError.InvalidDatatype,
				};
			}

			const verifyPresentation = async ({ presentationHeader, issuerHeader, claims }: PresentedJpt): Promise<Result<{
				valid: true,
				presentationHeader: jwp.JwpHeader,
				issuerHeader: jwp.JwpHeader,
				claims: JptClaims,
				holderPublicKey: JWK,
			}, CredentialVerificationError>> => {
				if (opts.expectedAudience && (presentationHeader.aud !== opts.expectedAudience)) {
					return {
						success: false,
						error: CredentialVerificationError.KbJwtVerificationFailedUnexpectedAudience,
					};
				}
				if (opts.expectedNonce && (presentationHeader.nonce !== opts.expectedNonce)) {
					return {
						success: false,
						error: CredentialVerificationError.KbJwtVerificationFailedUnexpectedNonce,
					};
				}

				for (const issuerPublicKey of args.issuerPublicKeys) {
					const PK = importIssuerPublicJwk(issuerPublicKey, 'experimental/SplitBBSv2.1');
					try {
						await jwp.verify(PK, rawCredential);
					} catch (e) {
						// Invalid signature
						continue;
					}

					return {
						success: true,
						value: {
							valid: true,
							presentationHeader,
							issuerHeader,
							claims,
							holderPublicKey: null as unknown as JWK, // TODO: Eliminate horrible hack
						},
					};
				}

				return {
					success: false,
					error: CredentialVerificationError.InvalidSignature,
				};
			}

			const verifyIssuance = async ({ issuerHeader, claims, proof }: IssuedJpt): Promise<Result<{
				valid: true,
				issuerHeader: jwp.JwpHeader,
				claims: JptClaims,
				holderPublicKey: JWK,
			}, CredentialVerificationError>> => {
				for (const issuerPublicKey of [issuerHeader.jwk, ...args.issuerPublicKeys]) {
					try {
						await jwp.confirm(issuerPublicKey, rawCredential);
					} catch (e) {
						// Invalid signature
						continue;
					}

					let dpk;
					try {
						dpk = JSON.parse(new TextDecoder().decode(proof[1]));
					} catch (e) {
						return {
							success: false,
							error: CredentialVerificationError.CannotExtractHolderPublicKey,
						};
					}

					return {
						success: true,
						value: {
							valid: true,
							issuerHeader,
							claims,
							holderPublicKey: dpk,
						},
					};
				}

				return {
					success: false,
					error: CredentialVerificationError.InvalidSignature,
				};
			}

			const parsedCredential = parseJpt(rawCredential);
			if ("presentationHeader" in parsedCredential) {
				return verifyPresentation(parsedCredential);
			} else {
				return verifyIssuance(parsedCredential);
			}

		},
	}
}
