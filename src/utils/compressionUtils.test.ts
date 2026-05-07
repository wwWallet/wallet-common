import { describe, expect, it } from 'vitest';
import {
	CompactEncrypt,
	compactDecrypt,
	generateKeyPair
} from 'jose';

import { compressionUtils } from './compressionUtils';

const enc = new TextEncoder();
const dec = new TextDecoder();

describe('compressionUtils (JOSE v5 style)', () => {
	it('round-trips compression + decompression', async () => {
		const input = enc.encode('hello world');

		const compressed =
			await compressionUtils.deflateRaw(input);

		const decompressed =
			await compressionUtils.inflateRaw(compressed);

		expect(decompressed).toEqual(input);
	});

	it('compresses large payloads', async () => {
		const input = enc.encode('a'.repeat(10_000));

		const compressed =
			await compressionUtils.deflateRaw(input);

		expect(compressed.byteLength).toBeLessThan(
			input.byteLength
		);
	});

	it('JOSE encrypt/decrypt works with manual compression', async () => {
		const { publicKey, privateKey } =
			await generateKeyPair('RSA-OAEP-256');

		const payload = enc.encode(
			JSON.stringify({
				sub: '123',
				data: 'hello compressed world'
			})
		);

		// v5: MANUAL compression BEFORE encryption
		const compressed =
			await compressionUtils.deflateRaw(payload);

		const jwe = await new CompactEncrypt(compressed)
			.setProtectedHeader({
				alg: 'RSA-OAEP-256',
				enc: 'A256GCM'
			})
			.encrypt(publicKey);

		const { plaintext } = await compactDecrypt(
			jwe,
			privateKey
		);

		// v5: MANUAL decompression AFTER decryption
		const decompressed =
			await compressionUtils.inflateRaw(plaintext);

		expect(JSON.parse(dec.decode(decompressed))).toEqual(
			{
				sub: '123',
				data: 'hello compressed world'
			}
		);
	});

	it('fails when inflating non-compressed data', async () => {
		const input = enc.encode('not compressed');

		await expect(
			compressionUtils.inflateRaw(input)
		).rejects.toThrow();
	});

	it('does not mutate input buffers', async () => {
		const input = enc.encode('immutable');
		const copy = Uint8Array.from(input);

		await compressionUtils.deflateRaw(input);

		expect(input).toEqual(copy);
	});
});
