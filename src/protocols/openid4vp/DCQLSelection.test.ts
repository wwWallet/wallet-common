import { afterEach, describe, expect, it, vi } from 'vitest';
import { DcqlQuery } from 'dcql';
import { Jwt, SDJwt, pack } from '@sd-jwt/core';
import { IssuerSigned } from '@owf/mdoc';
import { generateKeyPair, SignJWT } from 'jose';
import { OpenID4VPServerAPI } from './OpenID4VPServerAPI';
import { OpenID4VPResponseMode } from './types';
import {
	dcqlRequirements,
	dcqlSelectionIsValid,
	reconcileDcqlSelection,
	validateDcqlPresentation,
	dcqlDisclosureFrame,
	expandDcqlPaths,
} from './DCQLSelection';

const hasher = async (data: string | ArrayBuffer, alg: string) =>
	new Uint8Array(
		await crypto.subtle.digest(
			alg,
			typeof data === 'string' ? new TextEncoder().encode(data) : data,
		),
	);
const issue = async (claims: Record<string, unknown>, frame: any = {}) => {
	const { packedClaims, disclosures } = await pack(claims, frame, { alg: 'sha-256', hasher }, () =>
		crypto.randomUUID(),
	);
	const jwt = new Jwt({
		header: { alg: 'ES256' },
		payload: { ...packedClaims, _sd_alg: 'sha-256' },
	});
	// Selection tests exercise real packing/disclosure; cryptography has separate tests.
	await jwt.sign(async () => 'test-signature');
	return new SDJwt({ jwt, disclosures }).encodeSDJwt();
};
const sd = (id: string, extra: any = {}) => ({
	id,
	format: 'dc+sd-jwt',
	meta: { vct_values: [`urn:synthetic:${id}`] },
	claims: [{ path: ['value'] }],
	...extra,
});
const md = (id: string, extra: any = {}) => ({
	id,
	format: 'mso_mdoc',
	meta: { doctype_value: `synthetic.${id}` },
	claims: [{ path: [`synthetic.${id}`, 'value'] }],
	...extra,
});
const query: any = {
	credentials: [
		sd('q0'),
		md('q1'),
		md('q2'),
		sd('q3'),
		md('q4'),
		md('q5', { multiple: true }),
		sd('q6'),
		sd('q7'),
	],
	credential_sets: [
		{ options: [['q0'], ['q1']] },
		{ options: [['q2'], ['q3'], ['q4', 'q5']] },
		{ required: false, options: [['q6']] },
		{ required: false, options: [['q7']] },
	],
};
const shaped = (id: string, value: unknown = true): any => {
	const descriptor = query.credentials.find((c: any) => c.id === id);
	return descriptor.format === 'mso_mdoc'
		? {
				credential_format: descriptor.format,
				doctype: `synthetic.${id}`,
				namespaces: { [`synthetic.${id}`]: { value } },
				cryptographic_holder_binding: true,
			}
		: {
				credential_format: descriptor.format,
				vct: `urn:synthetic:${id}`,
				claims: { value },
				cryptographic_holder_binding: true,
			};
};
const fakeIssuerSigned = (id: string, values: Record<string, unknown>) => ({
	issuerAuth: { mobileSecurityObject: { docType: `synthetic.${id}` } },
	issuerNamespaces: {
		issuerNamespaces: new Map([
			[
				`synthetic.${id}`,
				Object.entries(values).map(([elementIdentifier, elementValue]) => ({
					elementIdentifier,
					elementValue,
				})),
			],
		]),
	},
});
async function wallet(
	dcql: any,
	entries: { id: string; batchId: number; claims: Record<string, unknown>; frame?: any }[],
) {
	const { privateKey } = await generateKeyPair('ES256');
	const encodedMdocs = new Map<string, any>();
	const inventory = await Promise.all(
		entries.map(async (entry) => {
			const descriptor = dcql.credentials.find((c: any) => c.id === entry.id);
			const data =
				descriptor.format === 'mso_mdoc'
					? Buffer.from(`mdoc-${entry.batchId}`).toString('base64url')
					: await issue({ vct: descriptor.meta.vct_values[0], ...entry.claims }, entry.frame);
			if (descriptor.format === 'mso_mdoc')
				encodedMdocs.set(data, fakeIssuerSigned(entry.id, entry.claims));
			return { format: descriptor.format, data, batchId: entry.batchId };
		}),
	);
	vi.spyOn(IssuerSigned, 'decode').mockImplementation((bytes) =>
		encodedMdocs.get(Buffer.from(bytes).toString('base64url')),
	);
	const keystore = {
		signJwtPresentation: vi.fn(async (nonce: string, aud: string, presentations: string[]) => ({
			vpjwt:
				presentations[0] +
				(await new SignJWT({ nonce, aud }).setProtectedHeader({ alg: 'ES256' }).sign(privateKey)),
		})),
		generateDeviceResponse: vi.fn(async (mdoc: any, selectedQuery: any) => {
			const source = mdoc.documents[0];
			const paths = selectedQuery.credentials[0].claims.map((c: any) => c.path);
			const requestedNamespaces = paths.length
				? [...new Set<string>(paths.map((p: string[]) => p[0]))]
				: [source.docType];
			const namespaces = new Map(
				requestedNamespaces.map((ns) => [
					ns,
					(source.issuerSigned.issuerNamespaces.issuerNamespaces.get(ns) ?? []).filter(
						(item: any) => paths.some((p: any[]) => p[0] === ns && p[1] === item.elementIdentifier),
					),
				]),
			);
			return {
				deviceResponseMDoc: {
					encode: () => new Uint8Array([1]),
					documents: [
						{
							docType: source.docType,
							deviceSigned: {},
							issuerSigned: { issuerNamespaces: { issuerNamespaces: namespaces } },
						},
					],
				},
			};
		}),
	};
	const state: any = {
		dcql_query: dcql,
		client_id: 'x509_san_dns:verifier.invalid',
		nonce: 'fresh-nonce',
		response_uri: 'https://verifier.invalid/response',
		response_mode: OpenID4VPResponseMode.DIRECT_POST,
		client_metadata: { vp_formats: {} },
	};
	const helper = new OpenID4VPServerAPI({
		httpClient: {
			get: async () => {
				throw new Error('unexpected network');
			},
		},
		rpStateStore: { store: async () => {}, retrieve: async () => state },
		parseCredential: async (credential) => ({
			signedClaims: await (
				await SDJwt.fromEncode(credential.data, hasher)
			).getClaims<Record<string, unknown>>(hasher),
		}),
		selectCredentialForBatch: async (batch) => inventory.find((c) => c.batchId === batch) ?? null,
		strings: { purposeNotSpecified: '', allClaimsRequested: '' },
		keystore,
	});
	const result = await (helper as any).matchCredentialsToDCQL(inventory, dcql);
	return {
		helper,
		inventory,
		matches: result.mapping ? Object.fromEntries(result.mapping) : undefined,
		result,
		keystore,
	};
}
afterEach(() => vi.restoreAllMocks());

describe('DCQL combinations and presentation validation', () => {
	for (const first of ['q0', 'q1'])
		for (const second of [['q2'], ['q3'], ['q4', 'q5']]) {
			it(`accepts ${first} with ${second.join('+')} without unused alternatives or optional sets`, async () => {
				const response = Object.fromEntries([first, ...second].map((id) => [id, [shaped(id)]]));
				expect(validateDcqlPresentation(response, query).can_be_satisfied).toBe(true);
				const inventory = DcqlQuery.query(DcqlQuery.parse(query), Object.values(response).flat());
				expect(inventory.can_be_satisfied).toBe(true);
				expect(
					dcqlRequirements(query, inventory)[0].options.filter((o) => o.available),
				).toHaveLength(1);
				const ids = [first, ...second];
				const w = await wallet(
					query,
					ids.map((id, i) => ({ id, batchId: i + 1, claims: { value: true } })),
				);
				const result = await w.helper.createAuthorizationResponse(
					new Map(ids.map((id) => [id, w.matches[id].candidates])),
					w.inventory,
				);
				expect(Object.keys(JSON.parse(result.formData!.get('vp_token')!))).toEqual(ids);
				expect(w.matches.q6.candidates).toHaveLength(0);
			});
		}
	it('rejects either missing constituent of the compound option', () => {
		for (const id of ['q4', 'q5'])
			expect(() =>
				validateDcqlPresentation({ q0: [shaped('q0')], [id]: [shaped(id)] }, query),
			).toThrow();
	});
	it('rejects unknown IDs, empty arrays, excess instances and nonmatching optional submissions', () => {
		const base = { q0: [shaped('q0')], q2: [shaped('q2')] };
		for (const extra of [
			{ other: [shaped('q0')] },
			{ q6: [] },
			{ q0: [shaped('q0'), shaped('q0')] },
			{ q6: [shaped('q7')] },
		])
			expect(() => validateDcqlPresentation({ ...base, ...extra }, query)).toThrow();
	});
	it('requires every query without credential_sets and defaults required to true', () => {
		expect(() =>
			validateDcqlPresentation({ q0: [shaped('q0')] }, {
				credentials: [sd('q0'), sd('q3')],
			} as any),
		).toThrow();
		const result = DcqlQuery.query(DcqlQuery.parse(query), [shaped('q0')]);
		expect(dcqlRequirements(query, result)[1].required).toBe(true);
		expect(result.can_be_satisfied).toBe(false);
	});
});

describe('wallet matching, claim preference, and generation', () => {
	const claimsQuery: any = {
		credentials: [
			sd('q0', {
				claims: [
					{ id: 'a', path: ['flags', '18'], values: [true] },
					{ id: 'b', path: ['fallback'] },
				],
				claim_sets: [['a'], ['b']],
			}),
		],
	};
	it('prefers the first set and excludes alternative selective claims from preview and vp_token', async () => {
		const { helper, inventory, matches } = await wallet(claimsQuery, [
			{
				id: 'q0',
				batchId: 1,
				claims: { flags: { '18': true }, fallback: 'extra', mandatory: 'visible' },
				frame: { _sd: ['flags', 'fallback'] },
			},
		]);
		const candidate = matches.q0.candidates[0];
		expect(candidate.claimSetIndex).toBe(0);
		expect(candidate.disclosurePaths).toEqual([['flags', '18']]);
		expect(candidate.disclosedClaims.fallback).toBeUndefined();
		expect(candidate.disclosedClaims.mandatory).toBe('visible');
		const response = await helper.createAuthorizationResponse(
			new Map([['q0', [candidate]]]),
			inventory,
		);
		const token = JSON.parse(response.formData!.get('vp_token')!);
		const actual = await (await SDJwt.fromEncode(token.q0[0], hasher)).getClaims<any>(hasher);
		expect(actual.fallback).toBeUndefined();
		expect(actual.flags['18']).toBe(true);
		expect(actual).toEqual(candidate.disclosedClaims);
	});
	it('uses fallback when the first set fails and rejects when all fail', async () => {
		const fallback = await wallet(claimsQuery, [
			{
				id: 'q0',
				batchId: 1,
				claims: { flags: { '18': 'true' }, fallback: 'available' },
				frame: { _sd: ['flags', 'fallback'] },
			},
		]);
		expect(fallback.matches.q0.candidates[0].claimSetIndex).toBe(1);
		const unavailable = await wallet(claimsQuery, [
			{ id: 'q0', batchId: 1, claims: { flags: { '18': 'true' } } },
		]);
		expect(unavailable.result.error).toBe('insufficient_credentials');
	});
	it('does not interpret absent SD-JWT claims as permission to share every selective claim', async () => {
		const w = await wallet({ credentials: [sd('q0', { claims: undefined })] }, [
			{
				id: 'q0',
				batchId: 1,
				claims: { secret: 'hidden', mandatory: true },
				frame: { _sd: ['secret'] },
			},
		]);
		expect(w.matches.q0.candidates[0].disclosedClaims.secret).toBeUndefined();
		expect(w.matches.q0.candidates[0].disclosedClaims.mandatory).toBe(true);
	});
	it('deduplicates copies, generates distinct mdocs by query ID, and preserves object elements', async () => {
		const entries = ['q0', 'q4', 'q5', 'q5'].map((id, i) => ({
			id,
			batchId: i + 1,
			claims: { value: id === 'q5' ? { nested: i, extra: true } : true },
		}));
		const w = await wallet(query, [...entries, entries[3]]);
		expect(w.matches.q5.candidates).toHaveLength(2);
		const selection = new Map(['q0', 'q4', 'q5'].map((id) => [id, w.matches[id].candidates]));
		const result = await w.helper.createAuthorizationResponse(selection, w.inventory);
		const token = JSON.parse(result.formData!.get('vp_token')!);
		expect(Object.keys(token)).toEqual(['q0', 'q4', 'q5']);
		expect(token.q5).toHaveLength(2);
		expect(result.filteredVCEntities!.map((c) => c.batchId)).toEqual([1, 2, 3, 4]);
		expect(w.keystore.generateDeviceResponse).toHaveBeenCalledTimes(3);
	});
	it('refuses stale consent and incomplete selection', async () => {
		const w = await wallet(query, [
			{ id: 'q0', batchId: 1, claims: { value: true } },
			{ id: 'q2', batchId: 2, claims: { value: true } },
		]);
		await expect(
			w.helper.createAuthorizationResponse(new Map([['q0', w.matches.q0.candidates]]), w.inventory),
		).rejects.toThrow();
		const modified = { ...w.matches.q0.candidates[0], disclosurePaths: [['other']] };
		await expect(
			w.helper.createAuthorizationResponse(
				new Map([
					['q0', [modified]],
					['q2', w.matches.q2.candidates],
				]),
				w.inventory,
			),
		).rejects.toThrow('consent');
	});

	it('applies first and fallback claim sets to mdoc data-element selection', async () => {
		const q = {
			credentials: [
				md('q4', {
					claims: [
						{ id: 'a', path: ['synthetic.q4', 'preferred'] },
						{ id: 'b', path: ['synthetic.q4', 'fallback'] },
					],
					claim_sets: [['a'], ['b']],
				}),
			],
		};
		for (const [claims, index] of [
			[{ preferred: { nested: 'visible', extra: true }, fallback: 'hidden' }, 0],
			[{ fallback: 'visible' }, 1],
		] as const) {
			const w = await wallet(q, [{ id: 'q4', batchId: 1, claims }]);
			const candidate = w.matches.q4.candidates[0];
			expect(candidate.claimSetIndex).toBe(index);
			const response = await w.helper.createAuthorizationResponse(
				new Map([['q4', [candidate]]]),
				w.inventory,
			);
			expect(response.generatedVPs).toHaveLength(1);
			const passedQuery = w.keystore.generateDeviceResponse.mock.calls[0][1];
			expect(passedQuery.credentials[0].claims).toHaveLength(1);
			expect(passedQuery.credentials[0].claims[0].id).toBe(index === 0 ? 'a' : 'b');
			expect(Object.keys(candidate.disclosedClaims['synthetic.q4'])).toEqual([
				index === 0 ? 'preferred' : 'fallback',
			]);
		}
	});
	it('does not disclose mdoc data elements when claims is absent', async () => {
		const w = await wallet({ credentials: [md('q4', { claims: undefined })] }, [
			{ id: 'q4', batchId: 1, claims: { secret: 'hidden' } },
		]);
		const instance = w.matches.q4.candidates[0];
		expect(instance.disclosedClaims).toEqual({ 'synthetic.q4': {} });
		await w.helper.createAuthorizationResponse(new Map([['q4', [instance]]]), w.inventory);
		expect(w.keystore.generateDeviceResponse.mock.calls[0][1].credentials[0].claims).toEqual([]);
	});
	it('keeps every requested mdoc namespace and excludes other namespaces', async () => {
		const q = {
			credentials: [
				md('q4', {
					claims: [{ path: ['synthetic.q4', 'value'] }, { path: ['another', 'element'] }],
				}),
			],
		};
		const w = await wallet(q, [{ id: 'q4', batchId: 1, claims: { value: 'visible' } }]);
		const decode = vi.mocked(IssuerSigned.decode).getMockImplementation()!;
		vi.mocked(IssuerSigned.decode).mockImplementation((...args) => {
			const decoded = decode(...args);
			decoded.issuerNamespaces.issuerNamespaces.set('another', [
				{ elementIdentifier: 'element', elementValue: { nested: true } },
			] as any);
			decoded.issuerNamespaces.issuerNamespaces.set('unused', [
				{ elementIdentifier: 'secret', elementValue: 'hidden' },
			] as any);
			return decoded;
		});
		const result = await (w.helper as any).matchCredentialsToDCQL(w.inventory, q);
		const instance = result.mapping.get('q4').candidates[0];
		expect(instance.disclosedClaims).toEqual({
			'synthetic.q4': { value: 'visible' },
			another: { element: { nested: true } },
		});
		await w.helper.createAuthorizationResponse(new Map([['q4', [instance]]]), w.inventory);
	});
	it('does not silently skip a selected credential that becomes unavailable', async () => {
		const w = await wallet({ credentials: [sd('q0')] }, [
			{ id: 'q0', batchId: 1, claims: { value: true } },
		]);
		(w.helper as any).deps.selectCredentialForBatch = async () => null;
		await expect(
			w.helper.createAuthorizationResponse(new Map([['q0', w.matches.q0.candidates]]), w.inventory),
		).rejects.toThrow('unavailable');
		expect(w.keystore.signJwtPresentation).not.toHaveBeenCalled();
	});

	it('keeps overlapping references and removes abandoned selections', async () => {
		const overlap = {
			credentials: [sd('q0'), sd('q3')],
			credential_sets: [{ options: [['q0'], ['q3']] }, { required: false, options: [['q0']] }],
		};
		const w = await wallet(overlap, [
			{ id: 'q0', batchId: 1, claims: { value: true } },
			{ id: 'q3', batchId: 2, claims: { value: true } },
		]);
		let selection = reconcileDcqlSelection(w.matches, [0, null], new Map());
		expect([...selection.keys()]).toEqual(['q0']);
		selection = reconcileDcqlSelection(w.matches, [1, 0], selection);
		expect([...selection.keys()].sort()).toEqual(['q0', 'q3']);
		selection = reconcileDcqlSelection(w.matches, [1, null], selection);
		expect([...selection.keys()]).toEqual(['q3']);
		expect(dcqlSelectionIsValid(w.matches, [1, null], selection)).toBe(true);
		expect(dcqlSelectionIsValid(w.matches, [1, 0], selection)).toBe(false);
	});
});
