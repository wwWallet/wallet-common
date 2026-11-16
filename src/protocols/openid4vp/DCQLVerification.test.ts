import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, base64url } from 'jose';
import { SDJwt } from '@sd-jwt/core';
import { SDJWTVCVerifier } from '../../credential-verifiers/SDJWTVCVerifier';
import { OpenID4VPClientAPI } from './OpenID4VPClientAPI';
import { MemoryStore } from '../../core/MemoryStore';

const hasher = async (data: string | ArrayBuffer, alg: string) =>
	new Uint8Array(
		await crypto.subtle.digest(
			alg,
			typeof data === 'string' ? new TextEncoder().encode(data) : data,
		),
	);
describe('DCQL with verified issuer and holder signatures', () => {
	it('verifies and preserves every instance and rejects a bad optional signature, nonce, or audience', async () => {
		const issuer = await generateKeyPair('ES256');
		const holder = await generateKeyPair('ES256');
		const attacker = await generateKeyPair('ES256');
		const issuerJwk = await exportJWK(issuer.publicKey);
		const holderJwk = await exportJWK(holder.publicKey);
		const httpClient = {
			get: async () => {
				throw new Error('unexpected network');
			},
		} as any;
		const context = {
			clockTolerance: 0,
			subtle: crypto.subtle,
			lang: 'en',
			trustedCertificates: [],
		};
		const verifier = SDJWTVCVerifier({
			context,
			httpClient,
			pkResolverEngine: {
				register: () => {},
				resolve: async () => ({ success: true, value: { jwk: issuerJwk } }),
			},
		});
		const presentation = async (
			value: string | number,
			nonce = 'nonce',
			aud = 'aud',
			key = holder.privateKey,
		) => {
			const credential =
				(await new SignJWT({
					iss: 'https://issuer.invalid',
					vct: 'urn:synthetic:sample',
					value,
					eqf_level: value,
					cnf: { jwk: holderJwk },
				})
					.setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
					.sign(issuer.privateKey)) + '~';
			const sd_hash = base64url.encode(await hasher(credential, 'SHA-256'));
			return (
				credential +
				(await new SignJWT({ sd_hash, nonce, aud })
					.setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
					.setIssuedAt()
					.sign(key))
			);
		};
		const helper = new OpenID4VPClientAPI(
			new MemoryStore(),
			{ redirectUri: 'https://verifier.invalid/response', credentialEngineOptions: context },
			httpClient,
		);
		vi.spyOn(helper as any, 'initializeCredentialEngine').mockResolvedValue({
			sdJwtVerifier: verifier,
			credentialParsingEngine: {
				parse: async ({ rawCredential }: any) => ({
					success: true,
					value: {
						metadata: { credential: { format: 'dc+sd-jwt' } },
						signedClaims: await (await SDJwt.fromEncode(rawCredential, hasher)).getClaims(hasher),
					},
				}),
			},
		});
		const descriptor = (id: string, multiple = false) => ({
			id,
			multiple,
			format: 'dc+sd-jwt',
			meta: { vct_values: ['urn:synthetic:sample'] },
			claims: [{ path: ['value'] }],
		});
		const query = {
			credentials: [descriptor('r0', true), descriptor('r1')],
			credential_sets: [{ options: [['r0']] }, { required: false, options: [['r1']] }],
		};
		const validate = (token: any) =>
			(helper as any).validateDcqlVpToken(token, query, { audience: 'aud', nonce: 'nonce' });
		const first = await presentation('first');
		const second = await presentation('second');
		const valid = await validate({ r0: [first, second] });
		expect(valid.error).toBeUndefined();
		expect(valid.verifiedPresentations.r0.map((p: any) => [p.claims.value, p.holderBound])).toEqual(
			[
				['first', true],
				['second', true],
			],
		);
		const diplomaQuery = {
			credentials: [
				{
					id: 'graduate_diploma',
					format: 'dc+sd-jwt',
					meta: { vct_values: ['urn:synthetic:sample'] },
					claims: [{ path: ['eqf_level'], values: ['6', '7'] }],
				},
			],
		};
		const validateDiploma = (vp: string) =>
			(helper as any).validateDcqlVpToken({ graduate_diploma: [vp] }, diplomaQuery, {
				audience: 'aud',
				nonce: 'nonce',
			});
		expect((await validateDiploma(await presentation('6'))).error).toBeUndefined();
		expect((await validateDiploma(await presentation('4'))).error).toBeDefined();
		const numericDiplomaQuery = {
			credentials: [
				{ ...diplomaQuery.credentials[0], claims: [{ path: ['eqf_level'], values: [6, 7] }] },
			],
		};
		expect(
			(
				await (helper as any).validateDcqlVpToken(
					{ graduate_diploma: [await presentation(6)] },
					numericDiplomaQuery,
					{ audience: 'aud', nonce: 'nonce' },
				)
			).error,
		).toBeUndefined();
		expect(
			(
				await (helper as any).validateDcqlVpToken(
					{ graduate_diploma: [await presentation('6')] },
					numericDiplomaQuery,
					{ audience: 'aud', nonce: 'nonce' },
				)
			).error,
		).toBeDefined();
		for (const invalid of [
			await presentation('bad', 'nonce', 'aud', attacker.privateKey),
			await presentation('bad', 'other'),
			await presentation('bad', 'nonce', 'other'),
		]) {
			expect((await validate({ r0: [first], r1: [invalid] })).error).toBeDefined();
			expect((await validate({ r0: [first, invalid] })).error).toBeDefined();
		}
		const unbound = first.slice(0, first.lastIndexOf('~') + 1);
		expect((await validate({ r0: [unbound] })).error).toBeDefined();
	});
});
