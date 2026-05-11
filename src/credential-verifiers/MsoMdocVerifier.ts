import { exportJWK, importX509, type JWK } from "jose";
import * as x509 from "@peculiar/x509";
import { CredentialVerificationError } from "../error";
import { Context, CredentialVerifier, PublicKeyResolverEngineI } from "../interfaces";
import { fromBase64Url } from "../utils/util";
import { DeviceResponse, IssuerSigned, Verifier, type MdocContext, CoseKey } from "@owf/mdoc";
import { buildOpenId4VpSessionTranscriptBytes } from "../protocols/openid4vp/sessionTranscript";
import { p256, p384 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';

export function MsoMdocVerifier(args: { context: Context, pkResolverEngine: PublicKeyResolverEngineI }): CredentialVerifier {
	let errors: { error: CredentialVerificationError, message: string }[] = [];
	const logError = (error: CredentialVerificationError, message: string): void => {
		errors.push({ error, message });
	}
	const isCertificateChainError = (err: Error): boolean => {
		const fingerprint = `${err.name} ${err.message}`.toLowerCase();
		return fingerprint.includes("certificate") && fingerprint.includes("chain");
	};

	const decodeBase64ToBytes = (value: string): Uint8Array => {
		if (typeof atob === "function") {
			const binary = atob(value);
			const bytes = new Uint8Array(binary.length);
			for (let i = 0; i < binary.length; i++) {
				bytes[i] = binary.charCodeAt(i);
			}
			return bytes;
		}
		if (typeof Buffer !== "undefined") {
			return new Uint8Array(Buffer.from(value, "base64"));
		}
		throw new Error("No base64 decoder available in this runtime");
	};

	const bytesToHex = (value: Uint8Array | ArrayBuffer): string => {
		const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
		return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
	};

	const certificatePemRegex = /-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g;
	const decodeCertificateToDer = (crt: string): Uint8Array => {
		const normalized = crt.includes("BEGIN CERTIFICATE")
			? crt.replace(certificatePemRegex, "")
			: crt.trim();
		return decodeBase64ToBytes(normalized);
	};

	const trustedCertificates = (args.context.trustedCertificates ?? []).map(
		(crt) => decodeCertificateToDer(crt)
	);

	const mdocContext: Pick<MdocContext, "crypto" | "cose" | "x509"> = {
		crypto: {
			digest: async ({ digestAlgorithm, bytes }) =>
				new Uint8Array(await args.context.subtle.digest(digestAlgorithm, bytes as Uint8Array<ArrayBuffer>)),
			random: () => {
				throw new Error("random is not used in verifier flow");
			},
			calculateEphemeralMacKey: async () => {
				throw new Error("calculateEphemeralMacKey is not used in verifier flow");
			},
		},
		cose: {
			mac0: {
				sign: async () => {
					throw new Error("mac0.sign is not used in verifier flow");
				},
				verify: async () => {
					throw new Error("mac0.verify is not used in verifier flow");
				},
			},
			sign1: {
				sign: async () => {
					throw new Error("sign1.sign is not used in verifier flow");
				},
				verify: async ({ sign1, key }) => {
					switch (sign1.signatureAlgorithmName) {
						case "ES256":
							return p256.verify(sign1.signature, sign1.toBeSigned, key.publicKey, { lowS: false });
						case "ES384":
							return p384.verify(sign1.signature, sign1.toBeSigned, key.publicKey, { lowS: false });
						case "EdDSA":
							return ed25519.verify(sign1.signature, sign1.toBeSigned, key.publicKey);
						default:
							throw new Error(`Unsupported COSE signature algorithm: ${sign1.signatureAlgorithmName}`);
					}
				},

			},
		},
		x509: {
			getIssuerNameField: ({ certificate, field }) =>
				new x509.X509Certificate(certificate).issuerName.getField(field),

			getPublicKey: async ({ certificate, alg }) => {
				const cert = new x509.X509Certificate(certificate);
				const key = await importX509(cert.toString(), alg, { extractable: true });
				return CoseKey.fromJwk((await exportJWK(key)) as unknown as Record<string, unknown>);
			},

			verifyCertificateChain: async ({ trustedCertificates, x5chain, now }) => {
				if (!x5chain.length) throw new Error("Certificate chain is empty");
				const leaf = new x509.X509Certificate(x5chain[0]);
				const chainBuilder = new x509.X509ChainBuilder({
					certificates: [
						...x5chain.map((c) => new x509.X509Certificate(c)),
						...trustedCertificates.map((c) => new x509.X509Certificate(c)),
					],
				});
				const chain = (await chainBuilder.build(leaf)).map((c) => new x509.X509Certificate(c.rawData)).reverse();
				for (let i = 0; i < chain.length; i++) {
					await chain[i]?.verify({ publicKey: chain[i - 1]?.publicKey, date: now ?? new Date() });
				}
			},

			getCertificateData: async ({ certificate }) => {
				const cert = new x509.X509Certificate(certificate);
				const thumbprint = new Uint8Array(await args.context.subtle.digest("SHA-1", cert.rawData));
				return {
					issuerName: cert.issuerName.toString(),
					subjectName: cert.subjectName.toString(),
					pem: cert.toString(),
					serialNumber: cert.serialNumber,
					thumbprint: bytesToHex(thumbprint),
					notBefore: cert.notBefore,
					notAfter: cert.notAfter,
				};
			},
		},
	};

	async function expirationCheck(issuerSigned: IssuerSigned): Promise<null | CredentialVerificationError.ExpiredCredential> {
		const { validUntil } = issuerSigned.issuerAuth.mobileSecurityObject.validityInfo;
		if (Math.floor(validUntil.getTime() / 1000) + args.context.clockTolerance < Math.floor(new Date().getTime() / 1000)) {
			logError(CredentialVerificationError.ExpiredCredential, "Credential is expired");
			return CredentialVerificationError.ExpiredCredential;
		}
		return null;
	}

	function extractHolderPublicKeyJwk(issuerSigned: IssuerSigned): JWK | null {
		const deviceKeyInfo = issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo;
		if (deviceKeyInfo == undefined) {
			logError(CredentialVerificationError.MsoMdocMissingDeviceKeyInfo, "MsoMdocMissingDeviceKeyInfo");
			return null;
		}

		const holderPublicKeyJwk = deviceKeyInfo.deviceKey.jwk;
		if (!("kty" in holderPublicKeyJwk)) {
			return null;
		}
		return holderPublicKeyJwk as unknown as JWK;
	}

	async function issuerSignedCheck(rawCredential: string): Promise<{ holderPublicKeyJwk: JWK | null }> {
		try {
			const credentialBytes = fromBase64Url(rawCredential);
			const issuerSigned = IssuerSigned.decode(credentialBytes);

			const expirationCheckRes = await expirationCheck(issuerSigned);
			if (expirationCheckRes !== null) {
				return { holderPublicKeyJwk: null };
			}

			if (trustedCertificates.length > 0 && mdocContext) {
				try {
					await issuerSigned.verify(
						{
							trustedCertificates,
							now: new Date(),
							skewSeconds: args.context.clockTolerance,
						},
						mdocContext
					);
				} catch {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { holderPublicKeyJwk: null };
				}
			}

			const holderPublicKeyJwk = extractHolderPublicKeyJwk(issuerSigned);
			return { holderPublicKeyJwk };
		}
		catch (err) {
			if (err instanceof Error) {
				if (isCertificateChainError(err)) {
					logError(CredentialVerificationError.InvalidCertificateChain, "Invalid Certificate chain: " + err.message);
				} else {
					logError(CredentialVerificationError.InvalidFormat, "Invalid IssuerSigned format: " + err.message);
				}
			}
		}
		return { holderPublicKeyJwk: null };
	}

	async function deviceResponseCheck(deviceResponse: DeviceResponse, opts: {
		expectedNonce?: string;
		expectedAudience?: string;
		holderNonce?: string;
		responseUri?: string;
		verifierEncryptionJwk?: JWK;
		handoverType?: "redirect" | "dc_api";
		dcApiOrigin?: string;
	}): Promise<{ holderPublicKeyJwk: JWK | null }> {
		try {
			const [parsedDocument] = deviceResponse.documents ?? [];
			if (!parsedDocument?.deviceSigned) {
				return { holderPublicKeyJwk: null };
			}

			const isBoundPresentationCheck =
				Boolean(opts.expectedAudience && opts.responseUri && opts.expectedNonce);

			if (isBoundPresentationCheck) {
				const expiredResult = await expirationCheck(parsedDocument.issuerSigned);
				if (expiredResult) {
					return { holderPublicKeyJwk: null };
				}
			}

			if (trustedCertificates.length > 0 && mdocContext) {
				try {
					await parsedDocument.issuerSigned.verify(
						{
							trustedCertificates,
							now: new Date(),
							skewSeconds: args.context.clockTolerance,
						},
						mdocContext
					);
				} catch {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { holderPublicKeyJwk: null };
				}
			}

			if (!isBoundPresentationCheck) {
				const expiredResult = await expirationCheck(parsedDocument.issuerSigned);
				if (expiredResult) {
					return { holderPublicKeyJwk: null };
				}
			}

			const holderPublicKeyJwk = extractHolderPublicKeyJwk(parsedDocument.issuerSigned);

			if (opts.expectedNonce) {
				const handoverType = opts.handoverType ?? "redirect";
				const handoverClientIdInput = handoverType === "dc_api" ? opts.dcApiOrigin : opts.expectedAudience;
				const handoverResponseUriInput = handoverType === "dc_api" ? "" : opts.responseUri;
				if (!handoverClientIdInput || !handoverResponseUriInput && handoverType === "redirect") {
					logError(CredentialVerificationError.MissingOpts, "Missing handover input for mdoc verification");
					return { holderPublicKeyJwk: null };
				}
				const handoverClientId = handoverClientIdInput;
				const handoverResponseUri = handoverType === "redirect" ? handoverResponseUriInput! : "";
				const expectedAudiences = [handoverClientId];
				if (handoverType === "redirect") {
					const schemeSeparatorIndex = handoverClientId.indexOf(":");
					if (schemeSeparatorIndex > 0 && schemeSeparatorIndex < handoverClientId.length - 1) {
						expectedAudiences.push(handoverClientId.slice(schemeSeparatorIndex + 1));
					}
				}

				let verified = false;
				let lastError: unknown = null;
				for (const expectedAudienceCandidate of (handoverType === "redirect" ? expectedAudiences : [handoverClientId])) {
					try {
						const sessionTranscript = await buildOpenId4VpSessionTranscriptBytes({
							subtle: args.context.subtle,
							handoverType,
							clientId: handoverType === "redirect" ? expectedAudienceCandidate : undefined,
							responseUri: handoverType === "redirect" ? handoverResponseUri : undefined,
							dcApiOrigin: handoverType === "dc_api" ? handoverClientId : undefined,
							nonce: opts.expectedNonce,
							verifierEncryptionJwk: opts.verifierEncryptionJwk,
						});

						await Verifier.verifyDeviceResponse(
							{
								deviceResponse,
								sessionTranscript,
								trustedCertificates,
								now: new Date(),
								skewSeconds: args.context.clockTolerance,
							},
							mdocContext
						);
						verified = true;
						break;
					} catch (err) {
						lastError = err;
					}
				}

				if (!verified && lastError) {
					throw lastError;
				}

				return { holderPublicKeyJwk };
			}

			return { holderPublicKeyJwk };
		}
		catch (err) {
			if (err instanceof Error) {
				if (isCertificateChainError(err)) {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { holderPublicKeyJwk: null };
				}
				else {
					logError(CredentialVerificationError.InvalidSignature, err.message);
				}
			}
			return { holderPublicKeyJwk: null };
		}
	}

	return {
		async verify({ rawCredential, opts }) {
			if (typeof rawCredential !== 'string') {
				return {
					success: false,
					error: CredentialVerificationError.InvalidDatatype,
				}
			}


			try {
				const decodedCred = fromBase64Url(rawCredential);
				const parsedMDOC = DeviceResponse.decode(decodedCred);
				const { holderPublicKeyJwk } = await deviceResponseCheck(parsedMDOC, opts);

				if (errors.length === 0 && holderPublicKeyJwk !== null) {
					return {
						success: true,
						value: {
							holderPublicKey: holderPublicKeyJwk,
						}
					};
				}

				if (errors.length > 0) {
					return {
						success: false,
						error: errors[0]?.error ?? CredentialVerificationError.UnknownProblem,
					};
				}
			}
			catch {
				const { holderPublicKeyJwk } = await issuerSignedCheck(rawCredential);
				if (errors.length === 0 && holderPublicKeyJwk !== null) {
					return {
						success: true,
						value: {
							holderPublicKey: holderPublicKeyJwk,
						}
					}
				}

				if (errors.length > 0) {
					return {
						success: false,
						error: errors[0]?.error ?? CredentialVerificationError.UnknownProblem,
					}
				}
			}

			console.error(errors);


			return {
				success: false,
				error: CredentialVerificationError.UnknownProblem
			}
		},
	}
}
