import { err, generateRandomIdentifier, GenericStore, ok, Result } from "../../core";
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
import { fromBase64Url, toBase64Url } from "../../utils/util";
import { TransactionData } from "./transactionData";
import { CredentialEngineOptions, CredentialIssuerMetadata, IacasResponse, OpenID4VPOptions, PresentationClaims, PresentationInfo, OpenID4VPClientResponseMode, RPState } from "./types";
import { DcqlPresentationResult } from 'dcql';
import { randomUUID } from "crypto";
import { exportJWK, generateKeyPair, importPKCS8, SignJWT, compactDecrypt, CompactDecryptResult, importJWK } from "jose";
import { serializeDcqlQuery } from "../../utils/serializeDcqlQuery";

export const OpenID4VPClientErrors = {
	MissingRPStateForKid: "missing_rpstate_for_kid",
	MissingRPState: "missing_rpstate",
	JWEDecryptionFailure: "jwe_decryption_failure",
	MissingState: "missing_state",
	PresentationAlreadyCompleted: "presentation_already_completed",
	MissingVpToken: "missing_vp_token",
	MissingPresentationSubmissionAndVpToken: "missing_presentation_submission_and_vp_token",
	SignedRequestObjectInvalidated: "signed_request_object_invalidated"
} as const;

export type OpenID4VPClientError = typeof OpenID4VPClientErrors[keyof typeof OpenID4VPClientErrors];

export interface OpenID4VPClientI {
	generateAuthorizationRequestURL(
		presentationRequest: any,
		sessionId: string,
		responseUri: string,
		baseUri: string,
		privateKeyPem: string,
		x5c: string[],
		responseMode: OpenID4VPClientResponseMode,
		callbackEndpoint?: string
	): Promise<{ url: URL; stateId: string; rpState: RPState }>;
	saveRPState(sessionId: string, state: RPState): Promise<void>;
	getPresentationBySessionId(
		sessionId?: string,
		cleanupSession?: boolean
	): Promise<{ status: true, presentations: unknown[], presentationInfo: PresentationInfo, rpState: RPState } | { status: false, error: Error }>;
	getRPStateByResponseCode(responseCode: string): Promise<RPState | null>;
	getRPStateBySessionId(sessionId: string): Promise<RPState | null>;
	getRPStateByKid(kid: string): Promise<RPState | null>;
	handleResponseJARM(response: any, kid: string): Promise<Result<RPState, OpenID4VPClientError>>;
	handleResponseDirectPost(
		state: string | undefined,
		vp_token: string | string[] | Record<string, string> | undefined,
		presentation_submission: any
	): Promise<Result<RPState, OpenID4VPClientError>>;
	getSignedRequestObject(sessionId: string): Promise<Result<string, OpenID4VPClientError>>;
}

const RESERVED_SDJWT_TOPLEVEL = new Set([
	'iss', 'sub', 'aud', 'nbf', 'exp', 'iat', 'jti', 'vct', 'cnf',
	'transaction_data_hashes', 'transaction_data_hashes_alg', 'vct#integrity'
]);
const decoder = new TextDecoder();
const encoder = new TextEncoder();

export function OpenID4VPClient(
	kvStore: GenericStore<string, RPState | string>,
	optionsInput: OpenID4VPOptions,
	httpClientInput: HttpClient
): OpenID4VPClientI {
	const rpStateKV = kvStore;
	const options = optionsInput;
	const httpClient = httpClientInput;

	async function initializeCredentialEngine() {
		console.log("Initializing credential engine...")

		const ctx = {
			clockTolerance: options.credentialEngineOptions.clockTolerance,
			subtle: options.credentialEngineOptions.subtle,
			lang: options.credentialEngineOptions.lang,
			trustedCertificates: [...options.credentialEngineOptions.trustedCertificates],
		};

		if (options.credentialEngineOptions.trustedCredentialIssuerIdentifiers) {
			const result = (await Promise.all(options.credentialEngineOptions.trustedCredentialIssuerIdentifiers.map(async (credentialIssuerIdentifier) =>
				httpClient.get(`${credentialIssuerIdentifier}/openid/.well-known/openid-credential-issuer`)
					.then((res) => res.data as CredentialIssuerMetadata)
					.catch((e) => { console.error(e); return null; })
			))).filter((r): r is CredentialIssuerMetadata => r !== null);

			const iacasResponses = (await Promise.all(result.map(async (metadata) => {
				if (metadata && metadata.mdoc_iacas_uri) {
					return httpClient.get(metadata.mdoc_iacas_uri).then((res) => res.data as IacasResponse).catch((e) => { console.error(e); return null; })
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
		credentialParsingEngine.register(SDJWTVCParser({ context: ctx, httpClient: httpClient }));
		console.log("Registered SDJWTVCParser...");
		credentialParsingEngine.register(MsoMdocParser({ context: ctx, httpClient: httpClient }));
		console.log("Registered MsoMdocParser...");

		const pkResolverEngine = PublicKeyResolverEngine();
		const openid4vcRendering = OpenID4VCICredentialRendering({ httpClient: httpClient });
		const credentialRendering = CredentialRenderingService();
		return {
			credentialParsingEngine,
			msoMdocVerifier: MsoMdocVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }),
			sdJwtVerifier: SDJWTVCVerifier({ context: ctx, pkResolverEngine: pkResolverEngine, httpClient: httpClient }),
			openid4vcRendering,
			credentialRendering,
		};
}
	async function generateAuthorizationRequestURL(presentationRequest: any, sessionId: string, responseUri: string, baseUri: string, privateKeyPem: string, x5c: string[], responseMode: OpenID4VPClientResponseMode, callbackEndpoint?: string): Promise<{ url: URL; stateId: string; rpState: RPState }> {

		console.log("Presentation Request: Session id used for authz req ", sessionId);

		const nonce = randomUUID();
		const state = sessionId;

		const client_id = new URL(responseUri).hostname

		const [rsaImportedPrivateKey, rpEphemeralKeypair] = await Promise.all([
			importPKCS8(privateKeyPem, 'ES256'),
			generateKeyPair('ECDH-ES')
		]);
		const [exportedEphPub, exportedEphPriv] = await Promise.all([
			exportJWK(rpEphemeralKeypair.publicKey),
			exportJWK(rpEphemeralKeypair.privateKey)
		]);

		exportedEphPub.kid = generateRandomIdentifier(8);
		exportedEphPriv.kid = exportedEphPub.kid;
		exportedEphPub.use = 'enc';
		let transactionDataObject: any[] = [];
		if (presentationRequest?.dcql_query?.credentials) {
			transactionDataObject = await Promise.all(presentationRequest?.dcql_query?.credentials
				.filter((cred: any) => cred._transaction_data_type !== undefined)
				.map(async (cred: any) => {
					if (!cred._transaction_data_type) {
						return null;
					}
					const txData = TransactionData(cred._transaction_data_type);
					if (!txData) {
						return null;
					}
					return await txData
						.generateTransactionDataRequestObject(cred.id);
				}));
		}

		transactionDataObject = transactionDataObject.filter((td) => td !== null);
		const signedRequestObject = await new SignJWT({
			response_uri: responseUri,
			aud: "https://self-issued.me/v2",
			iss: new URL(responseUri).hostname,
			client_id: "x509_san_dns:" + client_id,
			response_type: "vp_token",
			response_mode: responseMode,
			state: state,
			nonce: nonce,
			dcql_query: presentationRequest?.dcql_query?.credentials ? serializeDcqlQuery(JSON.parse(JSON.stringify(presentationRequest.dcql_query))) : null,
			client_metadata: {
				"jwks": {
					"keys": [
						exportedEphPub
					]
				},
				"authorization_encrypted_response_alg": "ECDH-ES",
				"authorization_encrypted_response_enc": "A256GCM",
				"vp_formats": {
					"vc+sd-jwt": {
						"sd-jwt_alg_values": [
							"ES256",
						],
						"kb-jwt_alg_values": [
							"ES256",
						]
					},
					"dc+sd-jwt": {
						"sd-jwt_alg_values": [
							"ES256",
						],
						"kb-jwt_alg_values": [
							"ES256",
						]
					},
					"mso_mdoc": {
						"alg": ["ES256"]
					}
				}
			},
			transaction_data: transactionDataObject.length > 0 ? transactionDataObject : undefined
		})
			.setIssuedAt()
			.setProtectedHeader({
				alg: 'ES256',
				x5c: x5c,
				typ: 'oauth-authz-req+jwt',
			})
			.sign(rsaImportedPrivateKey);
		const redirectUri = "openid4vp://cb";

		const newRpState: RPState = {
			session_id: sessionId,
			is_cross_device: true,
			signed_request: signedRequestObject,
			state,
			nonce,

			callback_endpoint: callbackEndpoint ?? null,

			audience: `x509_san_dns:${client_id}`,
			presentation_request_id:
				presentationRequest.id ??
				(presentationRequest.dcql_query as any)?.credentials?.[0]?.id,

			presentation_definition: null,
			dcql_query: presentationRequest?.dcql_query ?? null,

			rp_eph_kid: exportedEphPub.kid ?? "",
			rp_eph_pub: exportedEphPub,
			rp_eph_priv: exportedEphPriv,

			apv_jarm_encrypted_response_header: null,
			apu_jarm_encrypted_response_header: null,

			encrypted_response: null,
			vp_token: null,

			presentation_submission: null,
			response_code: null,

			claims: null,
			completed: null,
			presentation_during_issuance_session: null,

			date_created: Date.now(),
			};

		await saveRPState(sessionId, newRpState);
		await rpStateKV.set("key:" + exportedEphPub.kid, sessionId);

		// await rpStateRepository.save(newRpState);

		const requestUri = baseUri + "/verification/request-object?id=" + state;

		const redirectParameters = {
			client_id: "x509_san_dns:" + client_id,
			request_uri: requestUri
		};

		const searchParams = new URLSearchParams(redirectParameters);
		const authorizationRequestURL = new URL(redirectUri + "?" + searchParams.toString()); // must be openid4vp://cb

		console.log("AUTHZ REQ = ", authorizationRequestURL);
		return { url: authorizationRequestURL, stateId: state, rpState: newRpState };
	}

	async function saveRPState(sessionId: string, state: RPState): Promise<void> {
		await rpStateKV.set(`rpstate:${sessionId}`, state);
	}

	async function saveResponseCodeMapping(responseCode: string, sessionId: string): Promise<void> {
		await rpStateKV.set(`response_code:${responseCode}`, sessionId);
	}

	async function validateDcqlVpToken(
		vp_token_list: any,
		dcql_query: any,
		rpState: RPState
	): Promise<{ presentationClaims?: PresentationClaims, messages?: PresentationInfo, error?: Error }> {
		const presentationClaims: PresentationClaims = {};
		const ce = await initializeCredentialEngine();
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
							responseUri: options.redirectUri,
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

	async function getPresentationBySessionId(sessionId?: string, cleanupSession: boolean = false): Promise<{ status: true, presentations: unknown[], presentationInfo: PresentationInfo, rpState: RPState } | { status: false, error: Error }> {
		if (!sessionId) {
			console.error("getPresentationBySessionId: Invalid sessionId");
			const error = new Error("getPresentationBySessionId: Invalid sessionId");
			return { status: false, error };
		}
		const rpState = await rpStateKV.get(`rpstate:${sessionId}`) as RPState;

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
			const result = await validateDcqlVpToken(vp_token as any, rpState.dcql_query, rpState);
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
			// await rpStateRepository.save(rpState);
			saveRPState(sessionId, rpState);
			if (responseCode) {
				await rpStateKV.delete(`response_code:${responseCode}`);
			}
		}
		if (!rpState.claims && presentationClaims) {
			rpState.claims = presentationClaims;
			// await rpStateRepository.save(rpState);
			await saveRPState(sessionId, rpState);
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

	async function getRPStateByResponseCode(responseCode: string): Promise<RPState | null> {
		const sessionId = await rpStateKV.get(`response_code:${responseCode}`);

		if (!sessionId) {
			console.error("getPresentationByResponseCode: No session id for response code");
			return null;
		}

		const rpState = await rpStateKV.get(`rpstate:${sessionId}`) as RPState;
		if (!rpState) {
			console.error("getPresentationByResponseCode: Missing rpState for session id");
			return null;
		}

		return rpState;
	}

	async function getRPStateBySessionId(sessionId: string): Promise<RPState | null> {
		const rpState = await rpStateKV.get(`rpstate:${sessionId}`) as RPState;
		if (!rpState) {
			console.error("getRPStateBySessionId: Missing rpState for session id");
			return null;
		}

		return rpState;
	}

	async function getRPStateByKid(kid: string): Promise<RPState | null> {
		const sessionId = await rpStateKV.get("key:" + kid);
		if (!sessionId) {
			return null;
		}
		const rpState = await rpStateKV.get(`rpstate:${sessionId}`) as RPState;
		if (!rpState) {
			return null;
		}
		return rpState;
	}


	async function handleResponseJARM(response: any, kid :string): Promise<Result<RPState, OpenID4VPClientError>> {
		// get rpstate only to get the private key to decrypt the response

		const rpState = await getRPStateByKid(kid);
		if (!rpState) {
			return err(
				OpenID4VPClientErrors.MissingRPStateForKid,
				"responseHandler: Could not retrieve rpState from kid"
			);
		}

		const rp_eph_priv = await importJWK(rpState.rp_eph_priv, 'ECDH-ES');
		const result = await compactDecrypt(response, rp_eph_priv).then((r: any) => ({ data: r, err: null })).catch((err: any) => ({ data: null, err: err }));
		if (result.err) {
			const errorDescription = result.err instanceof Error ? result.err.message : String(result.err);
			console.error({ error: "JWE Decryption failure", error_description: result.err });
			console.log("Received JWE headers: ", JSON.parse(decoder.decode(fromBase64Url(response.split('.')[0]))));
			console.log("Received JWE: ", response);
			//ctx.res.status(500).send(error);
			return err(OpenID4VPClientErrors.JWEDecryptionFailure, errorDescription);
		}

		const { protectedHeader, plaintext } = result.data as CompactDecryptResult;
		console.log("Protected header = ", protectedHeader)
		const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { state: string | undefined, vp_token: string | undefined, presentation_submission: any };
		if (!payload?.state) {
			return err(OpenID4VPClientErrors.MissingState, "Missing state");
		}

		if (rpState.completed) {
			return err(OpenID4VPClientErrors.PresentationAlreadyCompleted, "Presentation flow already completed");
		}

		if (!payload.vp_token) {
			return err(OpenID4VPClientErrors.MissingVpToken, "Encrypted Response: vp_token is missing");
		}

		if (!payload.presentation_submission && !payload.vp_token) {
			return err(
				OpenID4VPClientErrors.MissingPresentationSubmissionAndVpToken,
				"Encrypted Response: presentation_submission and vp_token are missing"
			);
		}
		rpState.response_code = toBase64Url(encoder.encode(randomUUID()));
		await saveResponseCodeMapping(rpState.response_code, rpState.session_id);
		rpState.encrypted_response = response;
		rpState.presentation_submission = payload.presentation_submission;
		console.log("Encoding....")
		rpState.vp_token = toBase64Url(encoder.encode(JSON.stringify(payload.vp_token)));
		rpState.date_created = Date.now();
		rpState.apv_jarm_encrypted_response_header = protectedHeader.apv && typeof protectedHeader.apv == 'string' ? protectedHeader.apv as string : null;
		rpState.apu_jarm_encrypted_response_header = protectedHeader.apu && typeof protectedHeader.apu == 'string' ? protectedHeader.apu as string : null;
		rpState.completed = true;

		console.log("Stored rp state = ", rpState)
		//await rpStateRepository.save(rpState);
		await saveRPState(rpState.session_id, rpState);
		return ok(rpState);
	}

	async function handleResponseDirectPost(
		state: string | undefined,
		vp_token: string | string[] | Record<string, string> | undefined,
		presentation_submission: any
	): Promise<Result<RPState, OpenID4VPClientError>> {
		if (!state) {
			return err(OpenID4VPClientErrors.MissingState, "Missing state param");
		}

		if (!vp_token) {
			return err(OpenID4VPClientErrors.MissingVpToken, "Missing vp_token param");
		}

		const rpState = await rpStateKV.get(`rpstate:${state}`) as RPState;
		if (!rpState) {
			return err(OpenID4VPClientErrors.MissingRPState, "Couldn't get rp state with state");
		}

		if (rpState.completed) {
			return err(OpenID4VPClientErrors.PresentationAlreadyCompleted, "Presentation flow already completed");
		}

		rpState.response_code = toBase64Url(encoder.encode(randomUUID()));
		await saveResponseCodeMapping(rpState.response_code, rpState.session_id);
		rpState.presentation_submission = presentation_submission;
		rpState.vp_token = toBase64Url(encoder.encode(JSON.stringify(vp_token)));
		rpState.date_created = Date.now();
		rpState.completed = true;

		await saveRPState(rpState.session_id, rpState);
		return ok(rpState);
	}

	async function getSignedRequestObject(sessionId: string): Promise<Result<string, OpenID4VPClientError>>{
		const rpState = await getRPStateBySessionId(sessionId);

		if (!rpState) {
			return err(OpenID4VPClientErrors.MissingRPState, "rpState state could not be fetched with this id");
		}
		if (rpState.signed_request === "") {
			return err(OpenID4VPClientErrors.SignedRequestObjectInvalidated, "rpState state signed request object has been invalidated");
		}
		const signedRequest = rpState.signed_request;
		rpState.signed_request = "";
		await saveRPState(sessionId, rpState);
		return ok(signedRequest);
	}

	return {
		generateAuthorizationRequestURL,
		saveRPState,
		getPresentationBySessionId,
		getRPStateByResponseCode,
		getRPStateBySessionId,
		getRPStateByKid,
		handleResponseJARM,
		handleResponseDirectPost,
		getSignedRequestObject,
	};
}
