import { assert, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from 'jose';
import { getSdJwtHolderPublicKey } from './getSdJwtHolderPublicKey';
import { toBase64Url } from './util';

const encoder = new TextEncoder();

const buildSdJwt = async (payload: Record<string, unknown>) => {
	const { privateKey } = await generateKeyPair('ES256');
	const jwt = await new SignJWT(payload)
		.setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
		.sign(privateKey);
	return `${jwt}~`;
};

const disclosure = (name: string, value: unknown) =>
	toBase64Url(encoder.encode(JSON.stringify(['salt', name, value])));

describe('getSdJwtHolderPublicKey', () => {
	let holderPrivateKey: KeyLike;
	let holderJwk: JWK;

	beforeAll(async () => {
		const { privateKey, publicKey } = await generateKeyPair('ES256');
		holderPrivateKey = privateKey;
		holderJwk = await exportJWK(publicKey);
	});

	it('returns cnf.jwk', async () => {
		const credential = await buildSdJwt({ vct: 'urn:test', cnf: { jwk: holderJwk } });

		assert.deepEqual(await getSdJwtHolderPublicKey(credential), holderJwk);
	});

	it('returns cnf.jwk when the SD-JWT has disclosures', async () => {
		const credential =
			(await buildSdJwt({ vct: 'urn:test', cnf: { jwk: holderJwk } })) +
			`${disclosure('given_name', 'Ada')}~${disclosure('family_name', 'Lovelace')}~`;

		assert.deepEqual(await getSdJwtHolderPublicKey(credential), holderJwk);
	});

	it('returns cnf.jwk when a KB-JWT is attached', async () => {
		const kbJwt = await new SignJWT({ nonce: 'nonce', aud: 'https://verifier.example.com' })
			.setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
			.setIssuedAt()
			.sign(holderPrivateKey);
		const credential = (await buildSdJwt({ vct: 'urn:test', cnf: { jwk: holderJwk } })) + kbJwt;

		assert.deepEqual(await getSdJwtHolderPublicKey(credential), holderJwk);
	});

	it('returns null without cnf', async () => {
		const credential = await buildSdJwt({ vct: 'urn:test' });

		assert.isNull(await getSdJwtHolderPublicKey(credential));
	});

	it('returns null when cnf has only a kid', async () => {
		const credential = await buildSdJwt({ vct: 'urn:test', cnf: { kid: 'did:example:123#0' } });

		assert.isNull(await getSdJwtHolderPublicKey(credential));
	});

	it('throws for input that is not an SD-JWT', async () => {
		await expect(getSdJwtHolderPublicKey('not-an-sd-jwt')).rejects.toThrow();
	});
});
