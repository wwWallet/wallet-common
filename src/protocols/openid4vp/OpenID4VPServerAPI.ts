import {
	DcqlSelection,
	DcqlCredentialMatch,
	dcqlRequirements,
	validateDcqlPresentation,
	dcqlDisclosureFrame,
	dcqlClaimsFingerprint,
} from './DCQLSelection';
import { SDJwt } from '@sd-jwt/core';
import { IssuerSigned } from '@owf/mdoc';
import { base64url, EncryptJWT, importJWK, importX509, jwtVerify } from 'jose';
import { DcqlQuery } from 'dcql';
import { generateRandomIdentifier } from '../../utils';
import {
	OpenID4VPClientMetadata,
	OpenID4VPRelyingPartyState,
	OpenID4VPServerLastUsedNonceStore,
	OpenID4VPServerRequestVerifier,
	OpenID4VPServerMessages,
	OpenID4VPResponseMode,
	OpenID4VPJweEncryption,
	TransactionDataResponseGenerator,
	TransactionDataResponseGeneratorParams,
	TransactionDataResponseParams,
} from './types';
import { VerifiableCredentialFormat } from '../../types';
export const HandleAuthorizationRequestErrors = {
	NON_SUPPORTED_CLIENT_ID_SCHEME: 'non_supported_client_id_scheme',
	INSUFFICIENT_CREDENTIALS: 'insufficient_credentials',
	MISSING_DCQL_QUERY: 'missing_dcql_query',
	NONTRUSTED_VERIFIER: 'nontrusted_verifier',
	INVALID_RESPONSE_MODE: 'invalid_response_mode',
	OLD_STATE: 'old_state',
	INVALID_TRANSACTION_DATA: 'invalid_transaction_data',
	INVALID_TYP: 'invalid_jwt_typ',
	COULD_NOT_RESOLVE_REQUEST: 'could_not_resolve_request',
} as const;

export type HandleAuthorizationRequestError =
	(typeof HandleAuthorizationRequestErrors)[keyof typeof HandleAuthorizationRequestErrors];

type OpenID4VPServerKeystore = {
	signJwtPresentation(
		nonce: string,
		audience: string,
		presentations: string[],
		transactionDataResponseParams?: TransactionDataResponseParams,
	): Promise<{ vpjwt: string }>;
	generateDeviceResponse(
		mdoc: any,
		dcqlQuery: Record<string, unknown>,
		selectedCredentialId: string,
		nonce: string,
		clientId: string,
		responseUri: string,
		verifierEncryptionJwk?: JsonWebKey | Record<string, unknown>,
		handoverType?: 'redirect' | 'dc_api',
		dcApiOrigin?: string,
	): Promise<{ deviceResponseMDoc: any }>;
};

type OpenID4VPServerDeps<CredentialT extends OpenID4VPServerCredential, ParsedTransactionDataT> = {
	httpClient: {
		get: (url: string, options?: Record<string, unknown>) => Promise<{ data: unknown }>;
	};
	rpStateStore: {
		store(stateObject: OpenID4VPRelyingPartyState): Promise<void>;
		retrieve(): Promise<OpenID4VPRelyingPartyState>;
	};
	parseCredential: (
		credential: CredentialT,
	) => Promise<{ signedClaims: Record<string, unknown> } | null>;
	selectCredentialForBatch: (
		batchId: number,
		vcEntityList: CredentialT[],
	) => Promise<CredentialT | null>;
	keystore: OpenID4VPServerKeystore;
	strings: OpenID4VPServerMessages;
	lastUsedNonceStore?: OpenID4VPServerLastUsedNonceStore;
	parseTransactionData?: (
		transaction_data: string[],
		dcql_query: Record<string, unknown>,
	) => ParsedTransactionDataT[] | null;
	transactionDataResponseGenerator?: (
		params: TransactionDataResponseGeneratorParams,
	) => TransactionDataResponseGenerator;
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
	`-----BEGIN CERTIFICATE-----\n${certBase64.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
const supportedClientIdSchemes = new Set(['x509_san_dns', 'x509_hash']);
const preferredJweEncryptions = [
	OpenID4VPJweEncryption.A256GCM,
	OpenID4VPJweEncryption.A192GCM,
	OpenID4VPJweEncryption.A128GCM,
];

function decodeIssuerSignedCredential(credentialDataB64u: string): {
	issuerSigned: IssuerSigned;
	docType: string;
	namespaces: Record<string, Record<string, unknown>>;
} {
	const credentialBytes = base64url.decode(credentialDataB64u);
	const issuerSigned = IssuerSigned.decode(credentialBytes);
	const docType = issuerSigned.issuerAuth.mobileSecurityObject.docType;
	const issuerNamespaces = issuerSigned.issuerNamespaces?.issuerNamespaces ?? new Map();
	const namespaces = Object.fromEntries(
		[...issuerNamespaces].map(([name, items]) => [
			name,
			Object.fromEntries(items.map((item) => [item.elementIdentifier, item.elementValue])),
		]),
	);
	return { issuerSigned, docType, namespaces };
}

function isOpenID4VPResponseMode(value: unknown): value is OpenID4VPResponseMode {
	return (
		typeof value === 'string' &&
		Object.values(OpenID4VPResponseMode).includes(value as OpenID4VPResponseMode)
	);
}

function getSubtleCrypto(subtle?: SubtleCrypto): SubtleCrypto {
	if (subtle) return subtle;
	if (globalThis.crypto?.subtle) return globalThis.crypto.subtle;
	throw new Error('Missing SubtleCrypto implementation');
}

function getClientIdScheme(clientId: string): string {
	return clientId.split(':')[0];
}

async function calculateX509HashFromLeafCert(
	leafCertBase64: string,
	subtle?: SubtleCrypto,
): Promise<string> {
	let certBytes: Uint8Array;
	if (typeof Buffer !== 'undefined') {
		certBytes = Uint8Array.from(Buffer.from(leafCertBase64, 'base64'));
	} else {
		const binary = atob(leafCertBase64);
		certBytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) {
			certBytes[i] = binary.charCodeAt(i);
		}
	}
	const digest = await getSubtleCrypto(subtle).digest(
		'SHA-256',
		certBytes as Uint8Array<ArrayBuffer>,
	);
	return base64url.encode(new Uint8Array(digest));
}

export const retrieveKeys = async (
	S: OpenID4VPRelyingPartyState,
	httpClient: {
		get: (url: string, options?: Record<string, unknown>) => Promise<{ data: unknown }>;
	},
) => {
	if (S.client_metadata.jwks) {
		const rp_eph_pub_jwk = S.client_metadata.jwks.keys.filter((k) => k.use === 'enc')[0];
		if (!rp_eph_pub_jwk) {
			throw new Error('Could not find Relying Party public key for encryption');
		}
		if (!rp_eph_pub_jwk.alg) {
			throw new Error("alg is required in verifier's JWK");
		}
		return { rp_eph_pub_jwk, alg: rp_eph_pub_jwk.alg };
	}
	if (S.client_metadata.jwks_uri) {
		const response = await httpClient.get(S.client_metadata.jwks_uri).catch(() => null);
		if (
			response &&
			typeof response.data === 'object' &&
			response.data &&
			'keys' in (response.data as Record<string, unknown>)
		) {
			const keys = (response.data as { keys: any[] }).keys;
			const rp_eph_pub_jwk = keys.filter((k) => k.use === 'enc')[0];
			if (!rp_eph_pub_jwk) {
				throw new Error('Could not find Relying Party public key for encryption');
			}
			if (!rp_eph_pub_jwk.alg) {
				throw new Error("alg is required in verifier's JWK");
			}
			return { rp_eph_pub_jwk, alg: rp_eph_pub_jwk.alg };
		}
	}
	throw new Error('Could not find Relying Party public key for encryption');
};

export class OpenID4VPServerAPI<
	CredentialT extends OpenID4VPServerCredential,
	ParsedTransactionDataT,
> {
	private deps: OpenID4VPServerDeps<CredentialT, ParsedTransactionDataT>;

	constructor(deps: OpenID4VPServerDeps<CredentialT, ParsedTransactionDataT>) {
		this.deps = deps;
	}

	private parseAuthorizationParams(url: string) {
		const authorizationRequest = new URL(url);
		const searchParams = authorizationRequest.searchParams;

		return {
			client_id: searchParams.get('client_id'),
			response_uri: searchParams.get('response_uri'),
			nonce: searchParams.get('nonce'),
			state: searchParams.get('state') as string,
			client_metadata: searchParams.get('client_metadata')
				? JSON.parse(searchParams.get('client_metadata') as string)
				: null,
			response_mode: searchParams.get('response_mode')
				? JSON.parse(searchParams.get('response_mode') as string)
				: null,
			transaction_data: searchParams.get('transaction_data')
				? JSON.parse(searchParams.get('transaction_data') as string)
				: null,
			request_uri: searchParams.get('request_uri'),
			dcql_query: searchParams.get('dcql_query')
				? JSON.parse(searchParams.get('dcql_query') as string)
				: null,
		};
	}

	private async handleRequestUri(request_uri: string): Promise<
		| {
				payload: Record<string, unknown>;
				parsedHeader: Record<string, unknown>;
				leafCertBase64: string;
		  }
		| { error: HandleAuthorizationRequestError }
	> {
		const requestUriResponse = await this.deps.httpClient.get(request_uri, {});
		if (typeof requestUriResponse.data !== 'string') {
			return { error: HandleAuthorizationRequestErrors.COULD_NOT_RESOLVE_REQUEST };
		}
		const jwt = requestUriResponse.data;
		const [header, payload] = jwt.split('.');
		const parsedHeader = JSON.parse(decoder.decode(base64url.decode(header)));

		if (parsedHeader.typ !== 'oauth-authz-req+jwt') {
			return { error: HandleAuthorizationRequestErrors.INVALID_TYP };
		}
		const x5c = parsedHeader.x5c as string[];
		const leafCertBase64 = x5c?.[0];
		if (!leafCertBase64) {
			return { error: HandleAuthorizationRequestErrors.NONTRUSTED_VERIFIER };
		}
		const publicKey = await importX509(certFromB64(leafCertBase64), parsedHeader.alg);
		const verificationResult = await jwtVerify(jwt, publicKey).catch(() => null);
		if (verificationResult == null) {
			return { error: HandleAuthorizationRequestErrors.NONTRUSTED_VERIFIER };
		}
		const decodedPayload = JSON.parse(decoder.decode(base64url.decode(payload)));
		return { payload: decodedPayload, parsedHeader, leafCertBase64 };
	}

	private async matchCredentialsToDCQL(
		vcList: CredentialT[],
		dcqlJson: any,
	): Promise<
		| { mapping: Map<string, DcqlCredentialMatch>; descriptorPurpose: string }
		| { error: HandleAuthorizationRequestError }
	> {
		const descriptorPurpose = this.deps.strings.purposeNotSpecified ?? null;

		// shape all credentials in the wallet
		const shapedCredentials: any[] = [];
		for (const original of vcList) {
			// Resolve the copy before consent, so mandatory cryptographic claims (e.g. cnf)
			// in the preview describe the same copy that will be presented.
			const vc =
				original.batchId === undefined
					? original
					: ((await this.deps.selectCredentialForBatch(original.batchId, vcList)) ?? original);
			let shaped: any = { credential_format: vc.format };
			try {
				if (vc.format === VerifiableCredentialFormat.MSO_MDOC) {
					const { docType, namespaces } = decodeIssuerSignedCredential(vc.data);

					shaped = {
						credential_format: vc.format,
						doctype: docType,
						namespaces,
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
				shaped.sourceCredential = vc;
				shapedCredentials.push(shaped);
			} catch (e) {
				console.error('DCQL shaping error for this VC:', e);
			}
		}
		const parsedQuery = DcqlQuery.parse(dcqlJson);
		DcqlQuery.validate(parsedQuery);
		const result = DcqlQuery.query(parsedQuery, shapedCredentials);

		if (!result.can_be_satisfied)
			return { error: HandleAuthorizationRequestErrors.INSUFFICIENT_CREDENTIALS };
		const requirements = dcqlRequirements(dcqlJson, result);
		const mapping = new Map<string, DcqlCredentialMatch>();
		for (const credReq of dcqlJson.credentials) {
			const match = result.credential_matches[credReq.id];
			const candidates: DcqlCredentialMatch['candidates'] = [];
			if (match?.success)
				for (const vcMatch of match.valid_credentials) {
					const shaped = shapedCredentials[vcMatch.input_credential_index];
					if (shaped.batchId === undefined || candidates.some((c) => c.batchId === shaped.batchId))
						continue;
					const claimsResult = vcMatch.claims;
					const claimSet = claimsResult.success
						? claimsResult.valid_claim_sets.reduce((first, next) =>
								(next.claim_set_index ?? -1) < (first.claim_set_index ?? -1) ? next : first,
							)
						: undefined;
					const claimSetIndex = claimSet?.claim_set_index;
					const requestedClaims =
						claimSetIndex === undefined
							? (credReq.claims ?? [])
							: credReq.claims.filter((c: any) => credReq.claim_sets[claimSetIndex].includes(c.id));
					const disclosurePaths = requestedClaims.map(
						(c: any) => c.path ?? [c.namespace, c.claim_name],
					);
					let disclosedClaims: Record<string, unknown>;
					if (credReq.format === VerifiableCredentialFormat.MSO_MDOC) {
						// mdoc elements are indivisible. Absent claims requests no data elements.
						disclosedClaims = disclosurePaths.length
							? Object.fromEntries(
									[
										...new Set<string>(
											disclosurePaths.map((p: (string | number | null)[]) => p[0] as string),
										),
									].map((ns) => [
										ns,
										Object.fromEntries(
											disclosurePaths
												.filter((p: (string | number | null)[]) => p[0] === ns)
												.map((p: (string | number | null)[]) => [
													p[1],
													shaped.namespaces[ns][p[1] as string],
												]),
										),
									]),
								)
							: { [shaped.doctype]: {} };
					} else {
						const source = shaped.sourceCredential as CredentialT;
						const hasher = this.dcqlHasher();
						const jwt = await SDJwt.fromEncode(source.data, hasher);
						const presentation = await jwt.present(
							dcqlDisclosureFrame(disclosurePaths, shaped.claims),
							hasher,
						);
						disclosedClaims = await (
							await SDJwt.fromEncode(presentation, hasher)
						).getClaims<Record<string, unknown>>(hasher);
					}
					candidates.push({
						batchId: shaped.batchId,
						instanceId: shaped.sourceCredential.instanceId,
						credentialId: shaped.sourceCredential.credentialId,
						claimSetIndex,
						disclosurePaths,
						disclosedClaims,
					});
				}
			mapping.set(credReq.id, {
				credentials: candidates.map((c) => c.batchId),
				candidates,
				multiple: credReq.multiple ?? false,
				requirements,
				inventoryCanSatisfy: result.can_be_satisfied,
				failures: (match?.failed_credentials ?? []).map((failed) => ({
					inputCredentialIndex: failed.input_credential_index,
					metadata: !failed.meta.success,
					claims: !failed.claims.success,
					trustedAuthorities: !failed.trusted_authorities.success,
				})),
				...(!candidates.length
					? { failure: 'No credential satisfies the format, metadata and claim requirements.' }
					: {}),
				requestedFields: (credReq.claims ?? []).map((cl: any) => ({
					name: (cl.path ?? [cl.namespace, cl.claim_name]).join(' / '),
					purpose: descriptorPurpose,
					path: cl.path ?? [cl.namespace, cl.claim_name],
				})),
			});
		}

		return { mapping, descriptorPurpose };
	}

	private dcqlHasher() {
		const subtle = getSubtleCrypto(this.deps.subtle);
		return (data: string | ArrayBuffer, alg: string) =>
			subtle
				.digest(alg, typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data))
				.then((buf) => new Uint8Array(buf));
	}

	private async handleDCQLFlow(
		S: OpenID4VPRelyingPartyState,
		selectionMap: DcqlSelection,
		vcEntityList: CredentialT[],
	) {
		const { dcql_query, client_id, nonce, response_uri, transaction_data } = S;
		let verifierEncryptionJwk: JsonWebKey | Record<string, unknown> | undefined;
		let handoverType: 'redirect' | 'dc_api' = 'redirect';
		let dcApiOrigin: string | undefined;
		if (
			[OpenID4VPResponseMode.DIRECT_POST_JWT, OpenID4VPResponseMode.DC_API_JWT].includes(
				S.response_mode,
			)
		) {
			const { rp_eph_pub_jwk } = await retrieveKeys(S, this.deps.httpClient);
			verifierEncryptionJwk = rp_eph_pub_jwk as JsonWebKey | Record<string, unknown>;
		}
		if (S.response_mode === OpenID4VPResponseMode.DC_API_JWT) {
			handoverType = 'dc_api';
			dcApiOrigin = S.client_id.replace(/^origin:/, '');
		}
		const generatedVPs: string[] = [];
		const vpTokenObject: Record<string, string[]> = Object.create(null);
		const disclosed: Record<string, any[]> = Object.create(null);
		const matching = await this.matchCredentialsToDCQL(vcEntityList, dcql_query);
		if ('error' in matching) throw new Error(matching.error);
		const currentSelection: DcqlSelection = new Map();
		for (const [id, instances] of selectionMap) {
			const match = matching.mapping.get(id);
			if (
				!match ||
				!instances.length ||
				(!match.multiple && instances.length !== 1) ||
				new Set(instances.map((i) => i.batchId)).size !== instances.length
			)
				throw new Error('Invalid credential selection');
			currentSelection.set(
				id,
				instances.map((instance) => {
					const candidate = match.candidates.find((c) => c.batchId === instance.batchId);
					if (!candidate || dcqlClaimsFingerprint(candidate) !== dcqlClaimsFingerprint(instance))
						throw new Error('Credential selection changed; consent required');
					return candidate;
				}),
			);
		}
		// Validate the complete current choice before creating any holder-bound presentation.
		const selectedInventory = Object.fromEntries(
			[...currentSelection].map(([id, instances]) => {
				const descriptor = (dcql_query as any).credentials.find((c: any) => c.id === id);
				return [
					id,
					instances.map((instance) =>
						descriptor.format === VerifiableCredentialFormat.MSO_MDOC
							? {
									credential_format: descriptor.format,
									doctype: decodeIssuerSignedCredential(
										vcEntityList.find((vc) => vc.batchId === instance.batchId)!.data,
									).docType,
									namespaces: instance.disclosedClaims,
									cryptographic_holder_binding: true,
								}
							: {
									credential_format: descriptor.format,
									vct: instance.disclosedClaims.vct,
									claims: instance.disclosedClaims,
									cryptographic_holder_binding: true,
								},
					),
				];
			}),
		);
		validateDcqlPresentation(selectedInventory, dcql_query as any);

		const originalVCs: CredentialT[] = [];

		for (const [selectionKey, instances] of currentSelection) {
			for (const instance of instances) {
				const { batchId, disclosurePaths } = instance;
				const credential = await this.deps.selectCredentialForBatch(batchId, vcEntityList);
				if (!credential) throw new Error('Selected credential is unavailable');
				if (
					credential.instanceId !== instance.instanceId ||
					credential.credentialId !== instance.credentialId
				)
					throw new Error('Selected credential copy changed; consent required');

				if (
					credential.format === VerifiableCredentialFormat.VC_SDJWT ||
					credential.format === VerifiableCredentialFormat.DC_SDJWT
				) {
					const descriptor = (dcql_query as any).credentials.find(
						(c: any) => c.id === selectionKey,
					);
					if (!descriptor) {
						throw new Error(`No DCQL descriptor for id ${selectionKey}`);
					}
					const parsed = await this.deps.parseCredential(credential);
					if (!parsed) {
						throw new Error('Failed to parse credential');
					}
					const { signedClaims } = parsed;

					const frame = dcqlDisclosureFrame(disclosurePaths, signedClaims);
					const hasher = this.dcqlHasher();

					const sdJwt = await SDJwt.fromEncode(credential.data, hasher);
					const presentation = await sdJwt.present(frame, hasher);

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
						transactionDataResponseParams,
					);

					const generatedClaims = await (
						await SDJwt.fromEncode(vpjwt, hasher)
					).getClaims<Record<string, unknown>>(hasher);
					if (
						dcqlClaimsFingerprint(generatedClaims) !==
						dcqlClaimsFingerprint(instance.disclosedClaims)
					)
						throw new Error('Generated disclosure differs from consent');
					(disclosed[selectionKey] ??= []).push({
						credential_format: credential.format,
						vct: generatedClaims.vct,
						cryptographic_holder_binding: !vpjwt.endsWith('~'),
						claims: generatedClaims,
					});
					generatedVPs.push(vpjwt);
					(vpTokenObject[selectionKey] ??= []).push(vpjwt);
					originalVCs.push(credential);
				} else if (credential.format === VerifiableCredentialFormat.MSO_MDOC) {
					const descriptor = (dcql_query as any).credentials.find(
						(c: any) => c.id === selectionKey,
					);
					if (!descriptor) {
						throw new Error(`No DCQL descriptor for id ${selectionKey}`);
					}

					const { issuerSigned, docType } = decodeIssuerSignedCredential(credential.data);
					const effectiveDocType = docType;
					const mdoc = {
						documents: [
							{
								docType: effectiveDocType,
								issuerSigned,
							},
						],
					};

					const dcqlQueryWithClaims = {
						credentials: [
							{
								...descriptor,
								claim_sets: undefined,
								claims: (descriptor.claims ?? []).filter((c: any) =>
									disclosurePaths.some(
										(p) =>
											JSON.stringify(p) === JSON.stringify(c.path ?? [c.namespace, c.claim_name]),
									),
								),
							},
						],
					};

					const { deviceResponseMDoc } = await this.deps.keystore.generateDeviceResponse(
						mdoc,
						dcqlQueryWithClaims,
						selectionKey,
						nonce,
						client_id,
						response_uri,
						verifierEncryptionJwk,
						handoverType,
						dcApiOrigin,
					);
					const encodedDeviceResponse = base64url.encode(deviceResponseMDoc.encode());

					generatedVPs.push(encodedDeviceResponse);
					(vpTokenObject[selectionKey] ??= []).push(encodedDeviceResponse);
					const document = deviceResponseMDoc.documents[0];
					const namespaces = Object.fromEntries(
						[...document.issuerSigned.issuerNamespaces.issuerNamespaces].map(([ns, items]: any) => [
							ns,
							Object.fromEntries(
								items.map((item: any) => [item.elementIdentifier, item.elementValue]),
							),
						]),
					);
					if (dcqlClaimsFingerprint(namespaces) !== dcqlClaimsFingerprint(instance.disclosedClaims))
						throw new Error('Generated disclosure differs from consent');
					(disclosed[selectionKey] ??= []).push({
						credential_format: credential.format,
						doctype: document.docType,
						cryptographic_holder_binding: !!document.deviceSigned,
						namespaces,
					});
					originalVCs.push(credential);
				}
			}
		}
		validateDcqlPresentation(disclosed, dcql_query as any);

		const presentationSubmission = {
			id: generateRandomIdentifier(8),
			descriptor_map: Array.from(selectionMap.keys()).map((id) => ({ id, path: `$['${id}']` })),
		};

		const formData = new URLSearchParams();

		if (
			[OpenID4VPResponseMode.DIRECT_POST_JWT, OpenID4VPResponseMode.DC_API_JWT].includes(
				S.response_mode,
			)
		) {
			let jweEnc: string;
			if (S.client_metadata.encrypted_response_enc_values_supported) {
				const bestSupportedEnc = preferredJweEncryptions.find((enc) =>
					S.client_metadata.encrypted_response_enc_values_supported?.includes(enc),
				);
				if (!bestSupportedEnc) {
					throw new Error(
						'Could not find supported algorithm in encrypted_response_enc_values_supported',
					);
				}
				jweEnc = bestSupportedEnc;
			} else {
				jweEnc = OpenID4VPJweEncryption.A256GCM;
			}
			const { rp_eph_pub_jwk, alg } = await retrieveKeys(S, this.deps.httpClient);
			const rp_eph_pub = await importJWK(rp_eph_pub_jwk, alg);

			const jwePayload = {
				vp_token: vpTokenObject,
				state: S.state ?? undefined,
			};

			const jwe = await new EncryptJWT(jwePayload)
				.setProtectedHeader({
					alg: alg,
					enc: jweEnc,
					kid: rp_eph_pub_jwk.kid,
				})
				.encrypt(rp_eph_pub);

			formData.append('response', jwe);
		} else {
			formData.append('vp_token', JSON.stringify(vpTokenObject));
			if (S.state) formData.append('state', S.state);
		}

		return { formData, generatedVPs, presentationSubmission, filteredVCEntities: originalVCs };
	}

	async handleAuthorizationRequest(
		url: string,
		vcEntityList: CredentialT[],
	): Promise<
		| {
				conformantCredentialsMap: Map<string, DcqlCredentialMatch>;
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

		const client_id_scheme = getClientIdScheme(client_id);
		if (!supportedClientIdSchemes.has(client_id_scheme)) {
			return { error: HandleAuthorizationRequestErrors.NON_SUPPORTED_CLIENT_ID_SCHEME };
		}

		let parsedTransactionData: ParsedTransactionDataT[] | null = null;
		if (request_uri) {
			try {
				const result = await this.handleRequestUri(request_uri);
				if ('error' in result) {
					return result;
				}
				const { payload, parsedHeader, leafCertBase64 } = result;
				client_id = payload.client_id as string;
				const requestObjectClientIdScheme = getClientIdScheme(client_id);
				if (!supportedClientIdSchemes.has(requestObjectClientIdScheme)) {
					return { error: HandleAuthorizationRequestErrors.NON_SUPPORTED_CLIENT_ID_SCHEME };
				}
				if (requestObjectClientIdScheme === 'x509_hash') {
					const expectedClientId = `x509_hash:${await calculateX509HashFromLeafCert(leafCertBase64, this.deps.subtle)}`;
					if (client_id !== expectedClientId) {
						return { error: HandleAuthorizationRequestErrors.NONTRUSTED_VERIFIER };
					}
				}

				dcql_query = payload.dcql_query ?? dcql_query;
				response_uri = (payload.response_uri ?? payload.redirect_uri) as string;
				if (response_uri && !response_uri.startsWith('http')) {
					response_uri = `https://${response_uri}`;
				}
				client_metadata = payload.client_metadata as OpenID4VPClientMetadata;
				response_mode = payload.response_mode ?? response_mode;
				if (payload.transaction_data) {
					transaction_data = payload.transaction_data as string[];
					if (this.deps.parseTransactionData) {
						parsedTransactionData = this.deps.parseTransactionData(
							transaction_data,
							dcql_query as Record<string, unknown>,
						);
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
				console.error('Failed to handle request_uri', e);
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

		if (!isOpenID4VPResponseMode(response_mode)) {
			return { error: HandleAuthorizationRequestErrors.INVALID_RESPONSE_MODE };
		}
		console.log('VC entity list = ', vcEntityList);
		const vcList = vcEntityList.filter((cred) => cred.instanceId === 0);

		await this.deps.rpStateStore.store({
			nonce: nonce ?? '',
			response_uri: response_uri ?? '',
			client_id: client_id ?? '',
			state: state ?? '',
			client_metadata: client_metadata ?? { vp_formats: {} },
			response_mode,
			transaction_data: transaction_data ?? [],
			dcql_query,
		});

		let matchResult;
		if (dcql_query) {
			matchResult = await this.matchCredentialsToDCQL(vcList, dcql_query);
		}
		if (matchResult && 'error' in matchResult) {
			return { error: matchResult.error };
		}

		const { mapping, descriptorPurpose } = matchResult as {
			mapping: Map<string, DcqlCredentialMatch>;
			descriptorPurpose: string;
		};
		const verifierDomainName = client_id.includes('http') ? new URL(client_id).hostname : client_id;

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

	async createAuthorizationResponse(selectionMap: DcqlSelection, vcEntityList: CredentialT[]) {
		const S = await this.deps.rpStateStore.retrieve();

		if (!S || S.nonce === '' || (this.deps.lastUsedNonceStore?.get?.() ?? null) === S.nonce) {
			return {};
		}
		this.deps.lastUsedNonceStore?.set?.(S.nonce);

		const { formData, generatedVPs, presentationSubmission, filteredVCEntities } =
			await this.handleDCQLFlow(S, selectionMap, vcEntityList);

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
