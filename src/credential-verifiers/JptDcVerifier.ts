import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { JWK } from "jose";
import { parseJpt } from "../jpt";
import { importIssuerPublicJwk } from "../jwp";
import * as jwp from "../jwp";

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

			const parsedCredential = parseJpt(rawCredential);
			if (!("presentationHeader" in parsedCredential)) {
				return {
					success: false,
					error: CredentialVerificationError.InvalidDatatype,
				};
			}

			const { presentationHeader, claims } = parsedCredential;

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
						claims,
						holderPublicKey: null as unknown as JWK, // TODO: Eliminate horrible hack
					},
				};
			}

			return {
				success: false,
				error: CredentialVerificationError.InvalidSignature,
			};
		},
	}
}
