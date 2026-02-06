import { SDJwt } from "@sd-jwt/core";
import { cborDecode, cborEncode } from "@auth0/mdl/lib/cbor";
import { parse } from "@auth0/mdl";
import { base64url, EncryptJWT, importJWK, importX509, jwtVerify } from "jose";
import { DcqlPresentationResult, DcqlQuery } from "dcql";
import { generateRandomIdentifier } from "../../core";
import {
	OpenID4VPClientMetadata,
	OpenID4VPRelyingPartyState,
	OpenID4VPServerLastUsedNonceStore,
	OpenID4VPServerRequestVerifier,
	OpenID4VPServerStrings,
	ResponseMode,
	TransactionDataResponseGenerator,
	TransactionDataResponseParams,
} from "./types";
import { VerifiableCredentialFormat } from "../../types";
export const HandleAuthorizationRequestErrors = {
	NON_SUPPORTED_CLIENT_ID_SCHEME: "non_supported_client_id_scheme",
	INSUFFICIENT_CREDENTIALS: "insufficient_credentials",
	MISSING_DCQL_QUERY: "missing_dcql_query",
	NONTRUSTED_VERIFIER: "nontrusted_verifier",
	INVALID_RESPONSE_MODE: "invalid_response_mode",
	OLD_STATE: "old_state",
	INVALID_TRANSACTION_DATA: "invalid_transaction_data",
	INVALID_TYP: "invalid_jwt_typ",
	COULD_NOT_RESOLVE_REQUEST: "could_not_resolve_request",
} as const;

export type HandleAuthorizationRequestError = typeof HandleAuthorizationRequestErrors[keyof typeof HandleAuthorizationRequestErrors];

export type OpenID4VPServerKeystore = {
	signJwtPresentation(
		nonce: string,
		audience: string,
		presentations: string[],
		transactionDataResponseParams?: TransactionDataResponseParams
	): Promise<{ vpjwt: string }>;
	generateDeviceResponse(
		mdoc: any,
		presentationDefinition: Record<string, unknown>,
		apu: string | undefined,
		apv: string | undefined,
		clientId: string,
		responseUri: string
	): Promise<{ deviceResponseMDoc: any }>;
};

export type OpenID4VPServerDeps<CredentialT extends OpenID4VPServerCredential, ParsedTransactionDataT> = {
	httpClient: { get: (url: string, options?: Record<string, unknown>) => Promise<{ data: unknown }> };
	rpStateStore: {
		store(stateObject: OpenID4VPRelyingPartyState): Promise<void>;
		retrieve(): Promise<OpenID4VPRelyingPartyState>;
	};
	parseCredential: (credential: CredentialT) => Promise<{ signedClaims: Record<string, unknown> } | null>;
	selectCredentialForBatch: (batchId: number, vcEntityList: CredentialT[]) => Promise<CredentialT | null>;
	keystore: OpenID4VPServerKeystore;
	strings: OpenID4VPServerStrings;
	lastUsedNonceStore?: OpenID4VPServerLastUsedNonceStore;
	parseTransactionData?: (transaction_data: string[], dcql_query: Record<string, unknown>) => ParsedTransactionDataT[] | null;
	transactionDataResponseGenerator?: (params: { descriptor_id: string; dcql_query: Record<string, unknown> }) => TransactionDataResponseGenerator;
	verifyRequestUriAndCerts?: OpenID4VPServerRequestVerifier;
	subtle?: SubtleCrypto;
	randomUUID?: () => string;
};

export type OpenID4VPServerCredential = {
	format: string;
	data: string;
	batchId?: number;
	instanceId?: number;
	credentialId?: number;
};

const decoder = new TextDecoder();
const encoder = new TextEncoder();
const certFromB64 = (certBase64: string) =>
	`-----BEGIN CERTIFICATE-----\n${certBase64.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----`;

function isResponseMode(value: unknown): value is ResponseMode {
	return typeof value === "string" && Object.values(ResponseMode).includes(value as ResponseMode);
}

function getSubtleCrypto(subtle?: SubtleCrypto): SubtleCrypto {
	if (subtle) return subtle;
	if (globalThis.crypto?.subtle) return globalThis.crypto.subtle;
	throw new Error("Missing SubtleCrypto implementation");
}

function getRandomUUID(randomUUID?: () => string): string {
	if (randomUUID) return randomUUID();
	if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
	return generateRandomIdentifier(16);
}

const retrieveKeys = async (S: OpenID4VPRelyingPartyState, httpClient: { get: (url: string, options?: Record<string, unknown>) => Promise<{ data: unknown }> }) => {
	if (S.client_metadata.jwks) {
		const rp_eph_pub_jwk = S.client_metadata.jwks.keys.filter((k) => k.use === "enc")[0];
		if (!rp_eph_pub_jwk) {
			throw new Error("Could not find Relying Party public key for encryption");
		}
		return { rp_eph_pub_jwk };
	}
	if (S.client_metadata.jwks_uri) {
		const response = await httpClient.get(S.client_metadata.jwks_uri).catch(() => null);
		if (response && typeof response.data === "object" && response.data && "keys" in (response.data as Record<string, unknown>)) {
			const keys = (response.data as { keys: any[] }).keys;
			const rp_eph_pub_jwk = keys.filter((k) => k.use === "enc")[0];
			if (!rp_eph_pub_jwk) {
				throw new Error("Could not find Relying Party public key for encryption");
			}
			return { rp_eph_pub_jwk };
		}
	}
	throw new Error("Could not find Relying Party public key for encryption");
};

export class OpenID4VPServerAPI<CredentialT extends OpenID4VPServerCredential, ParsedTransactionDataT> {
	private deps: OpenID4VPServerDeps<CredentialT, ParsedTransactionDataT>;

	constructor(deps: OpenID4VPServerDeps<CredentialT, ParsedTransactionDataT>) {
		this.deps = deps;
	}

	private parseAuthorizationParams(url: string) {
		const authorizationRequest = new URL(url);
		const searchParams = authorizationRequest.searchParams;

		return {
			client_id: searchParams.get("client_id"),
			response_uri: searchParams.get("response_uri"),
			nonce: searchParams.get("nonce"),
			state: searchParams.get("state") as string,
			client_metadata: searchParams.get("client_metadata")
				? JSON.parse(searchParams.get("client_metadata") as string)
				: null,
			response_mode: searchParams.get("response_mode")
				? JSON.parse(searchParams.get("response_mode") as string)
				: null,
			transaction_data: searchParams.get("transaction_data")
				? JSON.parse(searchParams.get("transaction_data") as string)
				: null,
			request_uri: searchParams.get("request_uri"),
			dcql_query: searchParams.get("dcql_query")
				? JSON.parse(searchParams.get("dcql_query") as string)
				: null,
		};
	}

	private async handleRequestUri(request_uri: string): Promise<
		{ payload: Record<string, unknown>; parsedHeader: Record<string, unknown> } |
		{ error: HandleAuthorizationRequestError }
	> {
		const requestUriResponse = await this.deps.httpClient.get(request_uri, {});
		if (typeof requestUriResponse.data !== "string") {
			return { error: HandleAuthorizationRequestErrors.COULD_NOT_RESOLVE_REQUEST };
		}
		const jwt = requestUriResponse.data;
		const [header, payload] = jwt.split(".");
		const parsedHeader = JSON.parse(decoder.decode(base64url.decode(header)));

		if (parsedHeader.typ !== "oauth-authz-req+jwt") {
			return { error: HandleAuthorizationRequestErrors.INVALID_TYP };
		}
		const x5c = parsedHeader.x5c as string[];
		const publicKey = await importX509(certFromB64(x5c[0]), parsedHeader.alg);
		const verificationResult = await jwtVerify(jwt, publicKey).catch(() => null);
		if (verificationResult == null) {
			return { error: HandleAuthorizationRequestErrors.NONTRUSTED_VERIFIER };
		}
		const decodedPayload = JSON.parse(decoder.decode(base64url.decode(payload)));
		return { payload: decodedPayload, parsedHeader };
	}

	private async matchCredentialsToDCQL(vcList: CredentialT[], dcqlJson: any): Promise<
		| { mapping: Map<string, { credentials: number[]; requestedFields: { name: string; purpose: string; path?: (string | null)[] }[] }>; descriptorPurpose: string }
		| { error: HandleAuthorizationRequestError }
	> {
		const descriptorPurpose = this.deps.strings.purposeNotSpecified ?? null;

		// shape all credentials in the wallet
		const shapedCredentials: any[] = [];
		for (const vc of vcList) {
			let shaped: any = { credential_format: vc.format };
			try {
				if (vc.format === VerifiableCredentialFormat.MSO_MDOC) {
					const credentialBytes = base64url.decode(vc.data);
					const issuerSigned = cborDecode(credentialBytes);
					const issuerAuth = issuerSigned.get("issuerAuth") as Array<Uint8Array>;
					const payload = issuerAuth?.[2];
					const decodedIssuerAuthPayload = cborDecode(payload);
					const docType = decodedIssuerAuthPayload.data.get("docType");
					const envelope = {
						version: "1.0",
						documents: [
							new Map([
								["docType", docType],
								["issuerSigned", issuerSigned],
							]),
						],
						status: 0,
					};
					const mdoc = parse(cborEncode(envelope));
					const [document] = mdoc.documents;

					const nsName = document.issuerSignedNameSpaces[0];
					const nsObject = document.getIssuerNameSpace(nsName);

					shaped = {
						credential_format: vc.format,
						doctype: docType,
						namespaces: {
							[nsName]: nsObject,
						},
						batchId: vc.batchId,
						cryptographic_holder_binding: true,
					};
				} else {
					// SD-JWT shaping
					const parsed = await this.deps.parseCredential(vc);
					if (!parsed) {
						continue;
					}
					const { signedClaims } = parsed;
					shaped.vct = signedClaims.vct;
					shaped.claims = signedClaims;
					shaped.cryptographic_holder_binding = true;
					shaped.batchId = vc.batchId;
				}
				shapedCredentials.push(shaped);
			} catch (e) {
				console.error("DCQL shaping error for this VC:", e);
			}
		}
		if (shapedCredentials.length === 0) {
			return { error: HandleAuthorizationRequestErrors.INSUFFICIENT_CREDENTIALS };
		}
		const parsedQuery = DcqlQuery.parse(dcqlJson);
		DcqlQuery.validate(parsedQuery);
		const result = DcqlQuery.query(parsedQuery, shapedCredentials);

		const matches = result.credential_matches;

		function hasValidMatch(credId: string): boolean {
			const match = matches[credId];
			if (match?.success === false) {
				match.failed_credentials?.forEach((failedCreds: any) => {
					if (failedCreds.meta.success === false) {
						console.error("DCQL metadata issues: ", failedCreds.meta.issues);
					}
					if (!failedCreds.claims.success) {
						console.error("DCQL failed claims: ", failedCreds.claims);
					}
				});
			}
			return match?.success === true && Array.isArray(match.valid_credentials) && match.valid_credentials.length > 0;
		}

		const satisfied = dcqlJson.credentials.every((cred: any) => hasValidMatch(cred.id));
		if (!satisfied) {
			return { error: HandleAuthorizationRequestErrors.INSUFFICIENT_CREDENTIALS };
		}

		// Build the mapping for each credential query
		const mapping = new Map<string, { credentials: number[]; requestedFields: { name: string; purpose: string; path?: (string | null)[] }[] }>();
		for (const credReq of dcqlJson.credentials) {
			const match = result.credential_matches[credReq.id];
			const conforming: number[] = [];
			if (match?.success && match.valid_credentials) {
				for (const vcMatch of match.valid_credentials) {
					const shaped = shapedCredentials[vcMatch.input_credential_index];
					if (shaped?.batchId !== undefined) {
						conforming.push(shaped.batchId);
					}
				}
			}
			mapping.set(credReq.id, {
				credentials: conforming,
				requestedFields:
					!credReq.claims || credReq.claims.length === 0
						? [{ name: this.deps.strings.allClaimsRequested, purpose: descriptorPurpose, path: [null] }]
						: credReq.claims.map((cl: any) => ({
							name: cl.id || cl.path.join("."),
							purpose: descriptorPurpose,
							path: cl.path,
						})),
			});
		}

		const allConforming = Array.from(mapping.values()).flatMap((m) => m.credentials);
		if (allConforming.length === 0) {
			return { error: HandleAuthorizationRequestErrors.INSUFFICIENT_CREDENTIALS };
		}
		return { mapping, descriptorPurpose };
	}

	private convertDcqlToPresentationDefinition(dcql_query: any) {
		const pdId = getRandomUUID(this.deps.randomUUID);
		const input_descriptors = dcql_query.credentials.map((cred: any) => {
			const descriptorId = cred.meta?.doctype_value;

			const format: Record<string, any> = {};
			if (cred.format === "mso_mdoc") {
				format.mso_mdoc = { alg: ["ES256", "ES384", "EdDSA"] };
			}

			const fields = cred.claims.map((claim: any) => ({
				path: [`$['${cred.meta?.doctype_value}']${claim.path.slice(1).map((p: string) => `['${p}']`).join("")}`],
				intent_to_retain: claim.intent_to_retain ?? false,
			}));

			return {
				id: descriptorId,
				format,
				constraints: {
					limit_disclosure: "required",
					fields,
				},
			};
		});

		return {
			id: pdId,
			name: "DCQL-converted Presentation Definition",
			purpose: dcql_query.credential_sets?.[0]?.purpose ?? "No purpose defined",
			input_descriptors,
		};
	}

	private generatePresentationFrameForDCQLPaths(paths: string[][]): any {
		const frame: Record<string, any> = {};

		for (const rawSegments of paths) {
			let current = frame;
			for (let i = 0; i < rawSegments.length; i++) {
				const segment = rawSegments[i];
				if (i === rawSegments.length - 1) {
					current[segment] = true;
				} else {
					current[segment] = current[segment] || {};
					current = current[segment];
				}
			}
		}
		return frame;
	}

	private async handleDCQLFlow(
		S: OpenID4VPRelyingPartyState,
		selectionMap: Map<string, number>,
		vcEntityList: CredentialT[]
	) {
		const { dcql_query, client_id, nonce, response_uri, transaction_data } = S;
		let apu = undefined;
		let apv = undefined;
		const generatedVPs: string[] = [];
		const originalVCs: CredentialT[] = [];

		for (const [selectionKey, batchId] of selectionMap) {
			const credential = await this.deps.selectCredentialForBatch(batchId, vcEntityList);
			if (!credential) continue;

			if (
				credential.format === VerifiableCredentialFormat.VC_SDJWT ||
				credential.format === VerifiableCredentialFormat.DC_SDJWT
			) {
				const descriptor = (dcql_query as any).credentials.find((c: any) => c.id === selectionKey);
				if (!descriptor) {
					throw new Error(`No DCQL descriptor for id ${selectionKey}`);
				}
				const parsed = await this.deps.parseCredential(credential);
				if (!parsed) {
					throw new Error("Failed to parse credential");
				}
				const { signedClaims } = parsed;

				let paths: string[][];

				if (!descriptor.claims || descriptor.claims.length === 0) {
					paths = [];
					const getNestedPaths = (val: any, path: string[]) => {
						if (val === null || typeof val !== "object") {
							if (path.length) paths.push(path);
							return;
						}
						if (Array.isArray(val)) {
							if (path.length) {
								paths.push(path);
							}
							return;
						}
						const entries = Object.entries(val);
						if (entries.length === 0) {
							if (path.length) {
								paths.push(path);
							}
							return;
						}
						for (const [k, v] of entries) {
							getNestedPaths(v, path.concat(k));
						}
					};
					getNestedPaths(signedClaims, []);
				} else {
					paths = descriptor.claims.map((cl: any) => cl.path);
				}

				const frame = this.generatePresentationFrameForDCQLPaths(paths);
				const subtle = getSubtleCrypto(this.deps.subtle);
				const hasher = (data: string | ArrayBuffer, alg: string) => {
					const bytes = typeof data === "string" ? encoder.encode(data) : new Uint8Array(data);
					return subtle.digest(alg, bytes).then((buf) => new Uint8Array(buf));
				};

				const sdJwt = await SDJwt.fromEncode(credential.data, hasher);
				const presentation = credential.data.split("~").length - 1 > 1
					? await sdJwt.present(frame, hasher)
					: credential.data;

				const shaped = {
					credential_format: credential.format,
					vct: (signedClaims as any).vct,
					cryptographic_holder_binding: true,
					claims:
						!descriptor.claims || descriptor.claims.length === 0
							? signedClaims
							: Object.fromEntries(
								Object.entries(signedClaims).filter(([k]) =>
									descriptor.claims.some((cl: any) => cl.path.includes(k))
								)
							)
				};
				const presResult = DcqlPresentationResult.fromDcqlPresentation(
					{ [selectionKey]: [shaped] } as any,
					{ dcqlQuery: dcql_query as any }
				);
				if (!presResult.credential_matches[selectionKey]?.success) {
					throw new Error(`Presentation for '${selectionKey}' did not satisfy DCQL`);
				}

				let transactionDataResponseParams: TransactionDataResponseParams | undefined;
				if (transaction_data?.length && this.deps.transactionDataResponseGenerator) {
					const [res, err] = await this.deps
						.transactionDataResponseGenerator({ descriptor_id: selectionKey, dcql_query })
						.generateTransactionDataResponse(transaction_data);
					if (err) {
						throw err;
					}
					if (res) {
						transactionDataResponseParams = { ...res };
					}
				}

				const { vpjwt } = await this.deps.keystore.signJwtPresentation(
					nonce,
					client_id,
					[presentation],
					transactionDataResponseParams
				);

				generatedVPs.push(vpjwt);
				originalVCs.push(credential);
			} else if (credential.format === VerifiableCredentialFormat.MSO_MDOC) {
				const descriptor = (dcql_query as any).credentials.find((c: any) => c.id === selectionKey);
				if (!descriptor) {
					throw new Error(`No DCQL descriptor for id ${selectionKey}`);
				}
				const descriptorId = descriptor.meta?.doctype_value;
				const credentialBytes = base64url.decode(credential.data);
				const issuerSignedPayload = cborDecode(credentialBytes);

				const mdocStructure = {
					version: "1.0",
					documentErrors: [],
					documents: [
						new Map([
							["docType", descriptorId],
							["issuerSigned", issuerSignedPayload],
						]),
					],
					status: 0,
				};
				const encoded = cborEncode(mdocStructure);
				const mdoc = parse(encoded);
				const mdocGeneratedNonce = generateRandomIdentifier(8);
				apu = mdocGeneratedNonce;
				apv = nonce;

				let dcqlQueryWithClaims: any;
				if (!descriptor.claims || descriptor.claims.length === 0) {
					dcqlQueryWithClaims = JSON.parse(JSON.stringify(dcql_query));
					const nsName = mdoc.documents[0].issuerSignedNameSpaces[0];
					const ns = mdoc.documents[0].getIssuerNameSpace(nsName);

					const descriptorIndex = dcqlQueryWithClaims.credentials.findIndex((c: any) => c.id === selectionKey);
					if (descriptorIndex !== -1) {
						dcqlQueryWithClaims.credentials[descriptorIndex].claims = Object.keys(ns).map((key) => ({
							id: key,
							path: [descriptorId, key],
						}));
					}
				} else {
					dcqlQueryWithClaims = dcql_query;
				}

				const presentationDefinition = this.convertDcqlToPresentationDefinition(dcqlQueryWithClaims);
				const { deviceResponseMDoc } = await this.deps.keystore.generateDeviceResponse(
					mdoc,
					presentationDefinition,
					apu,
					apv,
					client_id,
					response_uri
				);
				const encodedDeviceResponse = base64url.encode(deviceResponseMDoc.encode());

				generatedVPs.push(encodedDeviceResponse);
				originalVCs.push(credential);
			}
		}

		// Always use DCQL query ID (selectionKey) as the key
		const vpTokenObject = Object.fromEntries(
			Array.from(selectionMap.keys()).map((key, idx) => [key, generatedVPs[idx]])
		);

		const presentationSubmission = {
			id: generateRandomIdentifier(8),
			descriptor_map: Array.from(selectionMap.keys()).map((id, idx) => ({ id, path: `$[${idx}]` })),
		};

		const formData = new URLSearchParams();

		if ([ResponseMode.DIRECT_POST_JWT, ResponseMode.DC_API_JWT].includes(S.response_mode) && S.client_metadata.authorization_encrypted_response_alg) {
			if (!S.client_metadata.authorization_encrypted_response_enc) {
				throw new Error("Missing authorization_encrypted_response_enc");
			}
			const { rp_eph_pub_jwk } = await retrieveKeys(S, this.deps.httpClient);
			const rp_eph_pub = await importJWK(rp_eph_pub_jwk, S.client_metadata.authorization_encrypted_response_alg);

			const jwePayload = {
				vp_token: vpTokenObject,
				state: S.state ?? undefined,
			};

			const jwe = await new EncryptJWT(jwePayload)
				.setKeyManagementParameters({ apu: new TextEncoder().encode(apu), apv: new TextEncoder().encode(apv) })
				.setProtectedHeader({
					alg: S.client_metadata.authorization_encrypted_response_alg,
					enc: S.client_metadata.authorization_encrypted_response_enc,
					kid: rp_eph_pub_jwk.kid,
				})
				.encrypt(rp_eph_pub);

			formData.append("response", jwe);
		} else {
			formData.append("vp_token", JSON.stringify(vpTokenObject));
			if (S.state) formData.append("state", S.state);
		}

		return { formData, generatedVPs, presentationSubmission, filteredVCEntities: originalVCs };
	}

	async handleAuthorizationRequest(
		url: string,
		vcEntityList: CredentialT[]
	): Promise<
		| {
				conformantCredentialsMap: Map<string, any>;
				verifierDomainName: string;
				verifierPurpose: string;
				parsedTransactionData: ParsedTransactionDataT[] | null;
			}
		| { error: HandleAuthorizationRequestError }
	> {
		let {
			client_id,
			response_uri,
			nonce,
			state,
			client_metadata,
			response_mode,
			transaction_data,
			request_uri,
			dcql_query,
		} = this.parseAuthorizationParams(url);

		if (!client_id) {
			return { error: HandleAuthorizationRequestErrors.COULD_NOT_RESOLVE_REQUEST };
		}

		const client_id_scheme = client_id.split(":")[0];
		if (client_id_scheme !== "x509_san_dns") {
			return { error: HandleAuthorizationRequestErrors.NON_SUPPORTED_CLIENT_ID_SCHEME };
		}

		let parsedTransactionData: ParsedTransactionDataT[] | null = null;
		if (request_uri) {
			try {
				const result = await this.handleRequestUri(request_uri);
				if ("error" in result) {
					return result;
				}
				const { payload, parsedHeader } = result;
				client_id = payload.client_id as string;

				dcql_query = payload.dcql_query ?? dcql_query;
				response_uri = (payload.response_uri ?? payload.redirect_uri) as string;
				if (response_uri && !response_uri.startsWith("http")) {
					response_uri = `https://${response_uri}`;
				}
				client_metadata = payload.client_metadata as OpenID4VPClientMetadata;
				response_mode = payload.response_mode ?? response_mode;
				if (payload.transaction_data) {
					transaction_data = payload.transaction_data as string[];
					if (this.deps.parseTransactionData) {
						parsedTransactionData = this.deps.parseTransactionData(transaction_data, dcql_query as Record<string, unknown>);
						if (parsedTransactionData === null) {
							return { error: HandleAuthorizationRequestErrors.INVALID_TRANSACTION_DATA };
						}
					}
				}
				state = payload.state as string;
				nonce = payload.nonce as string;

				if (this.deps.verifyRequestUriAndCerts) {
					await this.deps.verifyRequestUriAndCerts({ request_uri, response_uri, parsedHeader });
				}
			} catch (e) {
				console.error("Failed to handle request_uri", e);
				return { error: HandleAuthorizationRequestErrors.NONTRUSTED_VERIFIER };
			}
		}

		const lastUsedNonce = this.deps.lastUsedNonceStore?.get?.() ?? null;
		if (lastUsedNonce && lastUsedNonce === nonce) {
			return { error: HandleAuthorizationRequestErrors.OLD_STATE };
		}

		if (!dcql_query) {
			return { error: HandleAuthorizationRequestErrors.MISSING_DCQL_QUERY };
		}

		if (!isResponseMode(response_mode)) {
			return { error: HandleAuthorizationRequestErrors.INVALID_RESPONSE_MODE };
		}
		console.log("VC entity list = ", vcEntityList)
		const vcList = vcEntityList.filter((cred) => cred.instanceId === 0);

		await this.deps.rpStateStore.store({
			nonce: nonce ?? "",
			response_uri: response_uri ?? "",
			client_id: client_id ?? "",
			state: state ?? "",
			client_metadata: client_metadata ?? { vp_formats: {} },
			response_mode,
			transaction_data: transaction_data ?? [],
			dcql_query,
		});

		let matchResult;
		if (dcql_query) {
			matchResult = await this.matchCredentialsToDCQL(vcList, dcql_query);
		}
		if (matchResult && "error" in matchResult) {
			return { error: matchResult.error };
		}

		const { mapping, descriptorPurpose } = matchResult as {
			mapping: Map<string, any>;
			descriptorPurpose: string;
		};
		const verifierDomainName = client_id.includes("http")
			? new URL(client_id).hostname
			: client_id;

		if (mapping.size === 0) {
			throw new Error("Credentials don't satisfy any descriptor");
		}

		return {
			conformantCredentialsMap: mapping,
			verifierDomainName,
			verifierPurpose: descriptorPurpose,
			parsedTransactionData,
		};
	}

	async createAuthorizationResponse(selectionMap: Map<string, number>, vcEntityList: CredentialT[]) {
		const S = await this.deps.rpStateStore.retrieve();

		if (!S || S.nonce === "" || (this.deps.lastUsedNonceStore?.get?.() ?? null) === S.nonce) {
			return {};
		}
		this.deps.lastUsedNonceStore?.set?.(S.nonce);

		const { formData, generatedVPs, presentationSubmission, filteredVCEntities } = await this.handleDCQLFlow(
			S,
			selectionMap,
			vcEntityList
		);

		return {
			formData,
			generatedVPs,
			presentationSubmission,
			filteredVCEntities,
			response_uri: S.response_uri,
			client_id: S.client_id,
			state: S.state,
		};
	}
}
