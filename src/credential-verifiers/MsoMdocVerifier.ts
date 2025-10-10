import { JWK } from "jose";
import { CredentialVerificationError } from "../error";
import { Context, CredentialVerifier, PublicKeyResolverEngineI } from "../interfaces";
import { fromBase64Url } from "../utils/util";
import { DataItem, DeviceSignedDocument, IssuerSignedDocument, MDoc, parse, Verifier } from "@auth0/mdl";
import { IssuerSigned } from "@auth0/mdl/lib/mdoc/model/types";
import { cborDecode, cborEncode } from "@auth0/mdl/lib/cbor/";
import { COSEKeyToJWK } from "cose-kit";


export function MsoMdocVerifier(args: { context: Context, pkResolverEngine: PublicKeyResolverEngineI }): CredentialVerifier {
	console.log('MsoMdocVerifier initialized with trustedCertificates count:', args.context.trustedCertificates?.length);
	let errors: { error: CredentialVerificationError, message: string }[] = [];
	const logError = (error: CredentialVerificationError, message: string): void => {
		console.log('logError called with:', { error, message });
		errors.push({ error, message });
	}

	const verifier = new Verifier(args.context.trustedCertificates.map((crt) =>
		`-----BEGIN CERTIFICATE-----\n${crt}\n-----END CERTIFICATE-----`
	));
	console.log('Verifier created');

	const getSessionTranscriptBytesForOID4VPHandover = async (clId: string, respUri: string, nonce: string, mdocNonce: string) => {
		console.log('getSessionTranscriptBytesForOID4VPHandover inputs:', { clId, respUri, hasNonce: !!nonce, mdocNonce });
		const result = cborEncode(
			DataItem.fromData(
				[
					null,
					null,
					[
						await args.context.subtle.digest(
							'SHA-256',
							cborEncode([clId, mdocNonce]),
						),
						await args.context.subtle.digest(
							'SHA-256',
							cborEncode([respUri, mdocNonce]),
						),
						nonce
					]
				]
			)
		);
		console.log('getSessionTranscriptBytesForOID4VPHandover result length:', (result as Uint8Array)?.length);
		return result;
	}

	async function expirationCheck(issuerSigned: IssuerSigned): Promise<null | CredentialVerificationError.ExpiredCredential> {
		const { validFrom, validUntil, signed } = issuerSigned.issuerAuth.decodedPayload.validityInfo;
		console.log('expirationCheck validityInfo:', { validFrom, validUntil, signed, clockTolerance: args.context.clockTolerance });
		if (Math.floor(validUntil.getTime() / 1000) + args.context.clockTolerance < Math.floor(new Date().getTime() / 1000)) {
			logError(CredentialVerificationError.ExpiredCredential, "Credential is expired");
			return CredentialVerificationError.ExpiredCredential;
		}
		return null;
	}

	function extractHolderPublicKeyJwk(parsedDocument: IssuerSignedDocument): JWK | null {
		console.log('extractHolderPublicKeyJwk called');
		if (parsedDocument.issuerSigned.issuerAuth.decodedPayload.deviceKeyInfo == undefined) {
			logError(CredentialVerificationError.MsoMdocMissingDeviceKeyInfo, "MsoMdocMissingDeviceKeyInfo");
			return null;
		}

		const cosePublicKey = parsedDocument.issuerSigned.issuerAuth.decodedPayload.deviceKeyInfo.deviceKey;
		console.log('COSE public key present:', !!cosePublicKey);
		const holderPublicKeyJwk = COSEKeyToJWK(cosePublicKey);
		console.log('Extracted holderPublicKeyJwk kty:', (holderPublicKeyJwk as any)?.kty);
		return holderPublicKeyJwk as JWK;
	}

	async function issuerSignedCheck(rawCredential: string): Promise<{ holderPublicKeyJwk: JWK | null }> {
		console.log('issuerSignedCheck start');
		try {
			const credentialBytes = fromBase64Url(rawCredential);
			console.log('issuerSignedCheck decoded credentialBytes length:', credentialBytes.length);
			const issuerSigned: Map<string, unknown> = cborDecode(credentialBytes);
			console.log('issuerSignedCheck cbor decoded map keys:', Array.from(issuerSigned.keys?.() ?? []));
			console.log('issuerSignedCheck issuerSigned type:', Object.prototype.toString.call(issuerSigned));
			if (!issuerSigned.get('issuerAuth') || !(issuerSigned.get('issuerAuth') instanceof Array)) {
				console.log(CredentialVerificationError.InvalidDatatype, "InvalidDatatype: issuerAuth missing or not array");
			}
			const [header, _, payload, sig] = issuerSigned.get('issuerAuth') as Array<Uint8Array>;
			console.log('issuerSignedCheck issuerAuth lengths:', { header: header?.length, payload: payload?.length, sig: sig?.length });
			const decodedIssuerAuthPayload: DataItem = cborDecode(payload);
			const docType = decodedIssuerAuthPayload.data.get('docType');
			console.log('issuerSignedCheck docType:', docType);
			const m = {
				version: '1.0',
				documents: [new Map([
					['docType', docType],
					['issuerSigned', issuerSigned]
				])],
				status: 0
			};
			const encoded = cborEncode(m);
			console.log('issuerSignedCheck encoded length:', (encoded as Uint8Array)?.length);
			const mdoc = parse(encoded);
			console.log('issuerSignedCheck parsed mdoc documents count:', mdoc.documents?.length);
			const [parsedDocument] = mdoc.documents;
			const expirationCheckRes = await expirationCheck(parsedDocument.issuerSigned);
			console.log('issuerSignedCheck expirationCheckRes:', expirationCheckRes);
			if (expirationCheckRes !== null) {
				return { holderPublicKeyJwk: null };
			}

			if (parsedDocument.issuerSigned.issuerAuth.x5chain && args.context.trustedCertificates.length > 0) {
				console.log('issuerSignedCheck verifying x5chain with trusted certs');
				const { publicKey } = await parsedDocument.issuerSigned.issuerAuth.verifyX509Chain(args.context.trustedCertificates);
				console.log('issuerSignedCheck verifyX509Chain publicKey present:', !!publicKey);
				if (!publicKey) {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { holderPublicKeyJwk: null };
				}
				const verification = await parsedDocument.issuerSigned.issuerAuth.verify(publicKey);
				console.log('issuerSignedCheck issuerAuth verify result:', verification);
				if (verification !== true) {
					logError(CredentialVerificationError.InvalidSignature, "Invalid signature");
				}
				const holderPublicKeyJwk = extractHolderPublicKeyJwk(parsedDocument);

				return {
					holderPublicKeyJwk
				};
			}
			const holderPublicKeyJwk = extractHolderPublicKeyJwk(parsedDocument);
			console.log('issuerSignedCheck holderPublicKeyJwk present (no x5chain path):', !!holderPublicKeyJwk);

			return {
				holderPublicKeyJwk
			};

		}
		catch (err) {
			console.log('issuerSignedCheck caught error:', err);
			// @ts-ignore
			if (err?.name && err.name === "X509InvalidCertificateChain") {
				logError(CredentialVerificationError.InvalidCertificateChain, "Invalid Certificate chain: " + JSON.stringify(err))
			}
		}
		return { holderPublicKeyJwk: null };

	}

	async function deviceResponseCheck(mdoc: MDoc, opts: {
		expectedNonce?: string;
		expectedAudience?: string;
		holderNonce?: string;
		responseUri?: string;
	}): Promise<{ holderPublicKeyJwk: JWK | null }> {
		console.log('deviceResponseCheck start with opts:', opts);
		try {
			const [parsedDocument] = mdoc.documents as DeviceSignedDocument[];
			console.log('deviceResponseCheck documents length:', mdoc.documents?.length);
			if (!parsedDocument.deviceSigned) { // not a DeviceResponse
				console.log('deviceResponseCheck: not a DeviceResponse');
				return { holderPublicKeyJwk: null };
			}

			if (args.context.trustedCertificates.length > 0) {
				console.log('deviceResponseCheck verifying issuer with trusted certs');
				const res = await parsedDocument.issuerSigned.issuerAuth.verifyX509(args.context.trustedCertificates);
				console.log('deviceResponseCheck verifyX509 result:', res);
				if (!res) {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { holderPublicKeyJwk: null };
				}
			}

			const expiredResult = await expirationCheck(parsedDocument.issuerSigned);
			console.log('deviceResponseCheck expiredResult:', expiredResult);
			if (expiredResult) {
				return { holderPublicKeyJwk: null };
			}

			const holderPublicKeyJwk = extractHolderPublicKeyJwk(parsedDocument);
			console.log('deviceResponseCheck holderPublicKeyJwk present:', !!holderPublicKeyJwk);

			if (opts.expectedAudience && opts.responseUri && opts.expectedNonce && opts.holderNonce) {
				console.log('deviceResponseCheck performing full verifier.verify with session transcript');
				await verifier.verify(mdoc.encode(), {
					encodedSessionTranscript: await getSessionTranscriptBytesForOID4VPHandover(
						opts.expectedAudience,
						opts.responseUri,
						opts.expectedNonce,
						opts.holderNonce)
				});
				console.log('deviceResponseCheck verifier.verify completed');
				return { holderPublicKeyJwk };
			}

			console.log('deviceResponseCheck returning early with holderPublicKeyJwk');
			return { holderPublicKeyJwk: holderPublicKeyJwk }

		}
		catch (err) {
			console.log('deviceResponseCheck caught error:', err);
			if (err instanceof Error) {
				if (err.name === "X509InvalidCertificateChain") {
					logError(CredentialVerificationError.NotTrustedIssuer, "Issuer is not trusted");
					return { holderPublicKeyJwk: null };
				}
				else if (err.name === "MDLError") {
					logError(CredentialVerificationError.InvalidSignature, `MDLError: ${err.message}`);
				}
				else {
					console.error(err);
				}
			}
			return { holderPublicKeyJwk: null };
		}
	}

	return {
		async verify({ rawCredential, opts }) {
			console.log('verify called with rawCredential type:', typeof rawCredential, 'opts:', opts);
			if (typeof rawCredential !== 'string') {
				console.log('verify: InvalidDatatype');
				return {
					success: false,
					error: CredentialVerificationError.InvalidDatatype,
				}
			}


			try {
				const decodedCred = fromBase64Url(rawCredential)
				console.log('Decoded cred:', decodedCred);
				const parsedMDOC = parse(decodedCred);
				console.log('Parsed MDOC:', parsedMDOC);
				const { holderPublicKeyJwk } = await deviceResponseCheck(parsedMDOC, opts);
				console.log('verify deviceResponseCheck holderPublicKeyJwk:', holderPublicKeyJwk);

				if (errors.length === 0 && holderPublicKeyJwk !== null) {
					console.log('Holder public key JWK:', holderPublicKeyJwk);
					return {
						success: true,
						value: {
							holderPublicKey: holderPublicKeyJwk,
						}
					}
				}

				if (errors.length > 0) {
					console.log('Errors during mdoc verification:', errors);
					return {
						success: false,
						error: errors.length > 0 ?  errors[0].error : CredentialVerificationError.UnknownProblem,
					}
				}
			}
			catch (err) {
				console.log('verify parse/deviceResponse path threw, attempting issuerSignedCheck. Error:', err);
				const { holderPublicKeyJwk } = await issuerSignedCheck(rawCredential);
				console.log('verify issuerSignedCheck holderPublicKeyJwk:', holderPublicKeyJwk, 'errors:', errors);
				if (errors.length === 0 && holderPublicKeyJwk !== null) {
					return {
						success: true,
						value: {
							holderPublicKey: holderPublicKeyJwk,
						}
					}
				}

				if (errors.length > 0) {
					console.log('Errors during mdoc verification:', errors);
					return {
						success: false,
						error: errors.length > 0 ?  errors[0].error : CredentialVerificationError.UnknownProblem,
					}
				}
			}

			console.error("Errors in mdoc verification:", errors);

			return {
				success: false,
				error: CredentialVerificationError.UnknownProblem
			}
		},
	}
}
