import { Context, CredentialVerifier, PublicKeyResolverEngineI, HttpClient } from "../interfaces";
import { CredentialVerificationError } from "../error";
import { CustomResult, VerifiableCredentialFormat } from "../types";
import { exportJWK, importJWK, importX509, JWK, jwtVerify, KeyLike } from "jose";
import { fromBase64Url } from "../utils/util";
import { verifyCertificate } from "../utils/verifyCertificate";

export function JWTVCJSONVerifier(args: { context: Context, pkResolverEngine: PublicKeyResolverEngineI, httpClient: HttpClient }): CredentialVerifier {
	let errors: { error: CredentialVerificationError, message: string }[] = [];
	const logError = (error: CredentialVerificationError, message: string): void => {
		errors.push({ error, message });
	}

	const decoder = new TextDecoder();

	function canVerifyJwtVcJson(raw: unknown): raw is string {
		if (typeof raw !== "string") return false;

		const parts = raw.split(".");
		if (parts.length !== 3) return false;
		if (raw.includes("~")) return false;

		try {
			const header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
			if (
				header.typ === VerifiableCredentialFormat.VC_SDJWT ||
				header.typ === VerifiableCredentialFormat.DC_SDJWT
			) {
				return false;
			}
			return true;
		} catch {
			return false;
		}
	}

	const getHolderPublicKey = async (rawCredential: string): Promise<CustomResult<KeyLike | Uint8Array, CredentialVerificationError>> => {
		const parts = rawCredential.split(".");
		let payload;
		try {
			payload = JSON.parse(decoder.decode(fromBase64Url(parts[1])));
		} catch {
			return { success: false, error: CredentialVerificationError.InvalidFormat };
		}

		const cnf = payload.cnf as { jwk?: JWK } | undefined;
		if (cnf?.jwk) {
			let header;
			try {
				header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
			} catch {
				return { success: false, error: CredentialVerificationError.InvalidFormat };
			}
			try {
				const holderPublicKey = await importJWK(cnf.jwk, header.alg);
				return { success: true, value: holderPublicKey };
			} catch (err: unknown) {
				const message = err instanceof Error ? err.message : String(err);
				logError(CredentialVerificationError.CannotImportHolderPublicKey, `Could not import holder public key: ${message}`);
				return { success: false, error: CredentialVerificationError.CannotImportHolderPublicKey };
			}
		}

		return { success: false, error: CredentialVerificationError.CannotExtractHolderPublicKey };
	};

	const verifyIssuerSignature = async (rawCredential: string): Promise<CustomResult<{}, CredentialVerificationError>> => {
		const parts = rawCredential.split(".");
		let header;
		try {
			header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
		} catch {
			logError(CredentialVerificationError.InvalidFormat, "Invalid JWT header");
			return { success: false, error: CredentialVerificationError.InvalidFormat };
		}

		let payload;
		try {
			payload = JSON.parse(decoder.decode(fromBase64Url(parts[1])));
		} catch {
			logError(CredentialVerificationError.InvalidFormat, "Invalid JWT payload");
			return { success: false, error: CredentialVerificationError.InvalidFormat };
		}

		const alg = header.alg as string | undefined;

		// Try x5c certificate chain first
		const getIssuerPublicKey = async (): Promise<CustomResult<Uint8Array | KeyLike, CredentialVerificationError>> => {
			const x5c = header.x5c as string[] | undefined;
			if (x5c && x5c instanceof Array && x5c.length > 0 && typeof alg === "string") {
				const lastCertificate: string = x5c[x5c.length - 1];
				const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;
				const certificateValidationResult = await verifyCertificate(lastCertificatePem, args.context.trustedCertificates);
				const lastCertificateIsRootCa = args.context.trustedCertificates.map((c) => c.trim()).includes(lastCertificatePem);
				const rootCertIsTrusted = certificateValidationResult === true || lastCertificateIsRootCa;
				if (!rootCertIsTrusted) {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { success: false, error: CredentialVerificationError.NotTrustedIssuer };
				}

				try {
					const issuerPemCert = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
					const issuerPublicKey = await importX509(issuerPemCert, alg);
					return { success: true, value: issuerPublicKey };
				} catch (err) {
					logError(CredentialVerificationError.CannotImportIssuerPublicKey, `Cannot import issuer public key from x5c: ${err}`);
					return { success: false, error: CredentialVerificationError.CannotImportIssuerPublicKey };
				}
			}

			// Try kid / iss resolution via public key resolver
			if (typeof payload.iss === "string" && typeof alg === "string") {
				const publicKeyResolutionResult = await args.pkResolverEngine.resolve({ identifier: payload.iss });
				if (!publicKeyResolutionResult.success) {
					logError(CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
					return { success: false, error: CredentialVerificationError.CannotResolveIssuerPublicKey };
				}
				try {
					const publicKey = await importJWK(publicKeyResolutionResult.value.jwk, alg);
					return { success: true, value: publicKey };
				} catch (err: unknown) {
					const message = err instanceof Error ? err.message : String(err);
					logError(CredentialVerificationError.CannotImportIssuerPublicKey, `Cannot import resolved issuer public key: ${message}`);
					return { success: false, error: CredentialVerificationError.CannotImportIssuerPublicKey };
				}
			}

			logError(CredentialVerificationError.CannotResolveIssuerPublicKey, "CannotResolveIssuerPublicKey");
			return { success: false, error: CredentialVerificationError.CannotResolveIssuerPublicKey };
		};

		const issuerPublicKeyResult = await getIssuerPublicKey();
		if (!issuerPublicKeyResult.success) {
			return { success: false, error: issuerPublicKeyResult.error };
		}

		try {
			await jwtVerify(rawCredential, issuerPublicKeyResult.value, {
				clockTolerance: args.context.clockTolerance,
			});
		} catch (err: unknown) {
			if (err instanceof Error && err.name === "JWTExpired") {
				logError(CredentialVerificationError.ExpiredCredential, `Credential is expired: ${err}`);
				return { success: false, error: CredentialVerificationError.ExpiredCredential };
			}
			logError(CredentialVerificationError.InvalidSignature, `Issuer signature verification failed: ${err}`);
			return { success: false, error: CredentialVerificationError.InvalidSignature };
		}

		return { success: true, value: {} };
	};

	return {
		async verify({ rawCredential, opts }) {
			errors = [];

			if (!canVerifyJwtVcJson(rawCredential)) {
				return {
					success: false,
					error: CredentialVerificationError.VerificationProcessNotStarted,
				};
			}

			const issuerSignatureResult = await verifyIssuerSignature(rawCredential);
			if (!issuerSignatureResult.success) {
				return {
					success: false,
					error: errors.length > 0 ? errors[0].error : CredentialVerificationError.UnknownProblem,
				};
			}

			const publicKeyResult = await getHolderPublicKey(rawCredential);
			if (!publicKeyResult.success) {
				// Holder binding is optional for jwt_vc_json — return success with empty holderPublicKey
				return {
					success: true,
					value: {
						holderPublicKey: {} as JWK,
					},
				};
			}

			return {
				success: true,
				value: {
					holderPublicKey: await exportJWK(publicKeyResult.value),
				},
			};
		},
	};
}
