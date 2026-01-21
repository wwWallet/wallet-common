import { GenericStore } from "../../core";
import { MsoMdocParser } from "../../credential-parsers/MsoMdocParser";
import { SDJWTVCParser } from "../../credential-parsers/SDJWTVCParser";
import { MsoMdocVerifier } from "../../credential-verifiers/MsoMdocVerifier";
import { SDJWTVCVerifier } from "../../credential-verifiers/SDJWTVCVerifier";
import { OpenID4VCICredentialRendering } from "../../functions/openID4VCICredentialRendering";
import { HttpClient } from "../../interfaces";
import { ParsingEngine } from "../../ParsingEngine";
import { PublicKeyResolverEngine } from "../../PublicKeyResolverEngine";
import { CredentialRenderingService } from "../../rendering";
import { VerifiableCredentialFormat } from "../../types";
import { fromBase64Url } from "../../utils/util";
import { TransactionData } from "./transactionData";
import { CredentialEngineOptions, CredentialIssuerMetadata, IacasResponse, OpenID4VPOptions, PresentationClaims, PresentationInfo, RPState } from "./types";
import { DcqlPresentationResult } from 'dcql';

const RESERVED_SDJWT_TOPLEVEL = new Set([
	'iss', 'sub', 'aud', 'nbf', 'exp', 'iat', 'jti', 'vct', 'cnf',
	'transaction_data_hashes', 'transaction_data_hashes_alg', 'vct#integrity'
]);
const decoder = new TextDecoder();

export class OpenID4VPHelper {
	private rpStateKV: GenericStore<string, RPState | string>;
	private options: OpenID4VPOptions;
	private httpClient: HttpClient;

	constructor(kvStore: GenericStore<string, RPState | string>, options: OpenID4VPOptions, httpClient: HttpClient) {
		this.rpStateKV = kvStore;
		this.options = options;
		this.httpClient = httpClient;
	}

	private async initializeCredentialEngine() {
		console.log("Initializing credential engine...")

		const ctx = {
			clockTolerance: this.options.credentialEngineOptions.clockTolerance,
			subtle: this.options.credentialEngineOptions.subtle,
			lang: this.options.credentialEngineOptions.lang,
			trustedCertificates: [...this.options.credentialEngineOptions.trustedCertificates],
		};

		if (this.options.credentialEngineOptions.trustedCredentialIssuerIdentifiers) {
			const result = (await Promise.all(this.options.credentialEngineOptions.trustedCredentialIssuerIdentifiers.map(async (credentialIssuerIdentifier) =>
				this.httpClient.get(`${credentialIssuerIdentifier}/openid/.well-known/openid-credential-issuer`)
					.then((res) => res.data as CredentialIssuerMetadata)
					.catch((e) => { console.error(e); return null; })
			))).filter((r): r is CredentialIssuerMetadata => r !== null);

			const iacasResponses = (await Promise.all(result.map(async (metadata) => {
				if (metadata && metadata.mdoc_iacas_uri) {
					return this.httpClient.get(metadata.mdoc_iacas_uri).then((res) => res.data as IacasResponse).catch((e) => { console.error(e); return null; })
				}
				return null;
			}))).filter((r): r is IacasResponse => r !== null);

			for (const iacaResponse of iacasResponses) {
				const pemCertificates = iacaResponse.iacas?.map((cert) =>
					cert.certificate ? `-----BEGIN CERTIFICATE-----\n${cert.certificate}\n-----END CERTIFICATE-----\n` : null
				) ?? [];
				for (const pem of pemCertificates) {
					if (pem) {
						ctx.trustedCertificates.push(pem);
					}
				}
			}
		}

		const credentialParsingEngine = ParsingEngine();
		credentialParsingEngine.register(SDJWTVCParser({ context: ctx, httpClient: this.httpClient }));
		console.log("Registered SDJWTVCParser...");
		credentialParsingEngine.register(MsoMdocParser({ context: ctx, httpClient: this.httpClient }));
		console.log("Registered MsoMdocParser...");

		const pkResolverEngine = PublicKeyResolverEngine();
		const openid4vcRendering = OpenID4VCICredentialRendering({ httpClient: this.httpClient });
		const credentialRendering = CredentialRenderingService();
		return {
			credentialParsingEngine,
			msoMdocVerifier: MsoMdocVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }),
			sdJwtVerifier: SDJWTVCVerifier({ context: ctx, pkResolverEngine: pkResolverEngine, httpClient: this.httpClient }),
			openid4vcRendering,
			credentialRendering,
		};
}

	public saveRPState(sessionId: string, state: RPState): void {
		this.rpStateKV.set(`rpstate:${sessionId}`, state);
	}

	private saveResponseCodeMapping(responseCode: string, sessionId: string): void {
		this.rpStateKV.set(`response_code:${responseCode}`, sessionId);
	}

	private async validateDcqlVpToken(
		vp_token_list: any,
		dcql_query: any,
		rpState: RPState
	): Promise<{ presentationClaims?: PresentationClaims, messages?: PresentationInfo, error?: Error }> {
		const presentationClaims: PresentationClaims = {};
		const ce = await this.initializeCredentialEngine();
		const messages: PresentationInfo = {};

		for (const descriptor of dcql_query.credentials) {
			const vp = vp_token_list[descriptor.id];
			if (!vp) {
				return { error: new Error(`Missing VP for descriptor ${descriptor.id}`) };
			}

			try {
				// detect if SD-JWT (has ~) or mdoc (CBOR-encoded)
				if (typeof vp === 'string' && vp.includes('~')) {
					// ========== SD-JWT ==========
					try {
						const [kbjwt] = vp.split('~').reverse();
						const [_kbjwtEncodedHeader, kbjwtEncodedPayload, _kbjwtSig] = kbjwt.split('.');
						const kbjwtPayload = JSON.parse(decoder.decode(fromBase64Url(kbjwtEncodedPayload))) as Record<string, unknown>;
						if (Object.keys(kbjwtPayload).includes('transaction_data_hashes') && descriptor._transaction_data_type !== undefined) {
							const txData = TransactionData(descriptor._transaction_data_type);
							if (!txData) {
								return { error: new Error("specific transaction_data not supported error") };
							}
							const { status, message } = await txData.validateTransactionDataResponse(descriptor.id, {
								transaction_data_hashes: (kbjwtPayload as any).transaction_data_hashes as string[],
								transaction_data_hashes_alg: (kbjwtPayload as any).transaction_data_hashes_alg as string[] | undefined
							});
							console.log("Message: ", message)
							messages[descriptor.id] = [ message ];
							if (!status) {
								return { error: new Error("transaction_data validation error") };
							}
							console.log("VALIDATED TRANSACTION DATA");
						}
						else if (descriptor._transaction_data_type !== undefined) {
							return { error: new Error("transaction_data_hashes is missing from transaction data response") };
						}
					} catch (e) {
						console.error(e);
						return { error: new Error("transaction_data validation error") };
					}
					const verificationResult = await ce.sdJwtVerifier.verify({
						rawCredential: vp,
						opts: {
							expectedAudience: rpState.audience,
							expectedNonce: rpState.nonce,
						},
					});
					if (!verificationResult.success) {
						return { error: new Error(`SD-JWT verification failed for ${descriptor.id}: ${verificationResult.error}`) };
					}

					const parseResult = await ce.credentialParsingEngine.parse({ rawCredential: vp });
					if (!parseResult.success) {
						return { error: new Error(`Parsing SD-JWT failed for ${descriptor.id}: ${parseResult.error}`) };
					}

					const signedClaims = parseResult.value.signedClaims;
					const shaped = {
						vct: signedClaims.vct,
						credential_format: VerifiableCredentialFormat.DC_SDJWT,
						claims: signedClaims,
						cryptographic_holder_binding: true
					};

					const dcqlResult = DcqlPresentationResult.fromDcqlPresentation(
						/* @ts-ignore */
						{ [descriptor.id]: [shaped] },
						{ dcqlQuery: dcql_query }
					);
					if (!dcqlResult.credential_matches[descriptor.id]?.success) {
						return { error: new Error(`DCQL validation failed for ${descriptor.id}`) };
					}

					const output = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0].meta.output as any;
					if (
						output.credential_format === VerifiableCredentialFormat.VC_SDJWT ||
						output.credential_format === VerifiableCredentialFormat.DC_SDJWT
					) {
						const claims = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0]?.claims as any;
						const dcqlOut = claims?.valid_claim_sets?.[0]?.output as Record<string, unknown> | undefined;
						const signedClaims = parseResult.value.signedClaims as Record<string, unknown>;

						const requestedAll = descriptor?.claims == null;

						// Get all claims if no specific claims were requested
						const source: Record<string, unknown> =
							requestedAll
								? signedClaims
								: (dcqlOut && Object.keys(dcqlOut).length > 0 ? dcqlOut : signedClaims);

						const filteredSource = Object.fromEntries(
							Object.entries(source).filter(([k]) => !RESERVED_SDJWT_TOPLEVEL.has(k) && !k.startsWith('_'))
						);
						presentationClaims[descriptor.id] = Object.entries(filteredSource).map(([key, value]) => ({
							key,
							name: key,
							value: typeof value === 'object' ? JSON.stringify(value) : String(value),
						}));
					} else {
						return { error: new Error(`Unexpected credential_format for descriptor ${descriptor.id}`) };
					}
				} else {
					// ========== mdoc ==========
					const verificationResult = await ce.msoMdocVerifier.verify({
						rawCredential: vp,
						opts: {
							expectedAudience: rpState.audience,
							expectedNonce: rpState.nonce,
							holderNonce: rpState.apu_jarm_encrypted_response_header
								? decoder.decode(fromBase64Url(rpState.apu_jarm_encrypted_response_header))
								: undefined,
							responseUri: this.options.redirectUri,
						},
					});
					if (!verificationResult.success) {
						return { error: new Error(`mDoc verification failed for ${descriptor.id}: ${verificationResult.error}`) };
					}

					const parseResult = await ce.credentialParsingEngine.parse({ rawCredential: vp });
					if (!parseResult.success) {
						return { error: new Error(`Parsing mDoc failed for ${descriptor.id}: ${parseResult.error}`) };
					}
					const signedClaims = parseResult.value.signedClaims;
					const shaped = {
						credential_format: VerifiableCredentialFormat.MSO_MDOC,
						doctype: descriptor.meta?.doctype_value,
						cryptographic_holder_binding: true,
						namespaces: signedClaims
					};

					const dcqlResult = DcqlPresentationResult.fromDcqlPresentation(
						/* @ts-ignore */
						{ [descriptor.id]: [shaped] },
						{ dcqlQuery: dcql_query }
					);

					if (!dcqlResult.credential_matches[descriptor.id]?.success) {
						return { error: new Error(`DCQL validation failed for mdoc descriptor ${descriptor.id}`) };
					}
					const output = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0].meta.output as any;
					if (output.credential_format === VerifiableCredentialFormat.MSO_MDOC) {
						const claimsObject = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0].claims as any;
						if (!claimsObject) {
							return { error: new Error(`No claims found in mdoc for doctype ${descriptor.meta?.doctype_value}`) };
						}
						presentationClaims[descriptor.id] = Object.entries(claimsObject.valid_claim_sets[0].output[descriptor.meta?.doctype_value]).map(([key, value]) => ({
							key,
							name: key,
							value: typeof value === 'object' ? JSON.stringify(value) : String(value),
						}));
					} else {
						return { error: new Error(`Unexpected mdoc credential_format in output for descriptor ${descriptor.id}`) };
					}
				}
			} catch (e) {
				console.error(`Error processing descriptor ${descriptor.id}:`, e);
				return { error: new Error(`Internal error verifying or parsing VP for descriptor ${descriptor.id}`) };
			}
		}
		return { presentationClaims, messages };
	}

	public async getPresentationBySessionId(sessionId?: string, cleanupSession: boolean = false): Promise<{ status: true, presentations: unknown[], presentationInfo: PresentationInfo, rpState: RPState } | { status: false, error: Error }> {
		if (!sessionId) {
			console.error("getPresentationBySessionId: Invalid sessionId");
			const error = new Error("getPresentationBySessionId: Invalid sessionId");
			return { status: false, error };
		}
		const rpState = await this.rpStateKV.get(`rpstate:${sessionId}`) as RPState;

		if (!rpState) {
			console.error("Couldn't get rpState with the session_id " + sessionId);
			const error = new Error("Couldn't get rpState with the session_id " + sessionId);
			return { status: false, error };
		}

		if (!rpState.vp_token) {
			console.error("Presentation has not been sent. session_id " + sessionId);
			const error = new Error("Presentation has not been sent. session_id " + sessionId);
			return { status: false, error };
		}

		const vp_token = JSON.parse(decoder.decode(fromBase64Url(rpState.vp_token))) as string[] | string | Record<string, string>;

		let presentationClaims;
		let presentationInfo: PresentationInfo = {};
		let error: Error | undefined;
		if (rpState.dcql_query) {
			const result = await this.validateDcqlVpToken(vp_token as any, rpState.dcql_query, rpState);
			presentationClaims = result.presentationClaims;
			presentationInfo = result.messages ? result.messages : {};
			error = result.error;
		}
		if (error) {
			console.error(error)
			return { status: false, error };
		}
		if (cleanupSession) {
			const responseCode = rpState.response_code;
			rpState.state = "";
			rpState.session_id = ""; // invalidate session id
			rpState.response_code = "";
			// await this.rpStateRepository.save(rpState);
			this.saveRPState(sessionId, rpState);
			if (responseCode) {
				this.rpStateKV.delete(`response_code:${responseCode}`);
			}
		}
		if (!rpState.claims && presentationClaims) {
			rpState.claims = presentationClaims;
			// await this.rpStateRepository.save(rpState);
			this.saveRPState(sessionId, rpState);
		}
		if (rpState) {
			return {
				status: true,
				rpState: rpState,
				presentationInfo,
				presentations: Array.isArray(vp_token) ? vp_token : typeof vp_token === 'object' ? Object.values(vp_token) : [vp_token]
			};
		}
		const unkownErr = new Error("Uknown error");
		return { status: false, error: unkownErr };
	}

	public async getRPStateByResponseCode(responseCode: string): Promise<RPState | null> {
		const sessionId = this.rpStateKV.get(`response_code:${responseCode}`);

		if (!sessionId) {
			console.error("getPresentationByResponseCode: No session id for response code");
			return null;
		}

		const rpState = await this.rpStateKV.get(`rpstate:${sessionId}`) as RPState;
		if (!rpState) {
			console.error("getPresentationByResponseCode: Missing rpState for session id");
			return null;
		}

		return rpState;
	}

	public async getRPStateBySessionId(sessionId: string): Promise<RPState | null> {
		const rpState = await this.rpStateKV.get(`rpstate:${sessionId}`) as RPState;
		if (!rpState) {
			console.error("getRPStateBySessionId: Missing rpState for session id");
			return null;
		}

		return rpState;
	}
}
