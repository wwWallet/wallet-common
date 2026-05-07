// compressionOptions.test.ts
import { describe, it, expect } from 'vitest';
import {
	compactDecrypt,
	CompactEncrypt,
	generateKeyPair
} from 'jose';

import { compressionOptions } from './compressionOptions';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe('compressionOptions', () => {
	describe('deflateRaw/inflateRaw', () => {
		it('should round-trip UTF-8 text', async () => {
			const input = encoder.encode('hello world');

			const compressed = await compressionOptions.deflateRaw(input);
			const decompressed = await compressionOptions.inflateRaw(compressed);

			expect(decompressed).toBeInstanceOf(Uint8Array);
			expect(decoder.decode(decompressed)).toBe('hello world');
		});

		it('should round-trip empty payload', async () => {
			const input = new Uint8Array();

			const compressed = await compressionOptions.deflateRaw(input);
			const decompressed = await compressionOptions.inflateRaw(compressed);

			expect(decompressed).toEqual(input);
		});

		it('should round-trip binary data', async () => {
			const input = new Uint8Array([
				0,
				255,
				1,
				128,
				64,
				32,
				16,
				8,
				4,
				2,
				1
			]);

			const compressed = await compressionOptions.deflateRaw(input);
			const decompressed = await compressionOptions.inflateRaw(compressed);

			expect(Array.from(decompressed)).toEqual(Array.from(input));
		});

		it('should compress repetitive data efficiently', async () => {
			const input = encoder.encode('a'.repeat(10_000));

			const compressed = await compressionOptions.deflateRaw(input);

			expect(compressed.byteLength).toBeLessThan(input.byteLength);
		});

		it('should round-trip large payloads', async () => {
			const text = Array.from({ length: 5000 })
				.map((_, i) => `line-${i}`)
				.join('\n');

			const input = encoder.encode(text);

			const compressed = await compressionOptions.deflateRaw(input);
			const decompressed = await compressionOptions.inflateRaw(compressed);

			expect(decoder.decode(decompressed)).toBe(text);
		});

		it('should return Uint8Array instances', async () => {
			const input = encoder.encode('type check');

			const compressed = await compressionOptions.deflateRaw(input);
			const decompressed = await compressionOptions.inflateRaw(compressed);

			expect(compressed).toBeInstanceOf(Uint8Array);
			expect(decompressed).toBeInstanceOf(Uint8Array);
		});

		it('should reject invalid compressed payloads', async () => {
			const invalid = encoder.encode('not-valid-deflate-data');

			await expect(
				compressionOptions.inflateRaw(invalid)
			).rejects.toThrow();
		});

		it('should not mutate the original input buffer', async () => {
			const input = encoder.encode('immutable');
			const original = Uint8Array.from(input);

			await compressionOptions.deflateRaw(input);

			expect(input).toEqual(original);
		});
	});

	describe('JOSE integration (v5+ compatible)', () => {
		it('should interoperate with jose encryption/decryption', async () => {
			const { publicKey, privateKey } =
				await generateKeyPair('RSA-OAEP-256');

			const payload = encoder.encode(
				JSON.stringify({
					sub: '123',
					name: 'Alice',
					scope: ['openid', 'profile'],
					longText: 'a'.repeat(5000)
				})
			);

			// manually compress before encryption
			const compressed =
				await compressionOptions.deflateRaw(payload);

			const jwe = await new CompactEncrypt(compressed)
				.setProtectedHeader({
					alg: 'RSA-OAEP-256',
					enc: 'A256GCM'
				})
				.encrypt(publicKey);

			expect(typeof jwe).toBe('string');

			const result = await compactDecrypt(
				jwe,
				privateKey
			);

			// manually decompress after decryption
			const decompressed =
				await compressionOptions.inflateRaw(
					result.plaintext
				);

			expect(decompressed).toEqual(payload);

			expect(
				JSON.parse(
					decoder.decode(decompressed)
				)
			).toEqual({
				sub: '123',
				name: 'Alice',
				scope: ['openid', 'profile'],
				longText: 'a'.repeat(5000)
			});
		});

		it('should fail to inflate non-compressed decrypted payload', async () => {
			const { publicKey, privateKey } =
				await generateKeyPair('RSA-OAEP-256');

			const payload =
				encoder.encode('plain uncompressed payload');

			const jwe = await new CompactEncrypt(payload)
				.setProtectedHeader({
					alg: 'RSA-OAEP-256',
					enc: 'A256GCM'
				})
				.encrypt(publicKey);

			const result = await compactDecrypt(
				jwe,
				privateKey
			);

			await expect(
				compressionOptions.inflateRaw(
					result.plaintext
				)
			).rejects.toThrow();
		});
	});

	describe('runtime environment', () => {
		it('should expose CompressionStream APIs', () => {
			expect(globalThis.CompressionStream).toBeDefined();
			expect(globalThis.DecompressionStream).toBeDefined();
		});
	});
});
