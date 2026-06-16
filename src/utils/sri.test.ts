import { describe, it, expect, vi, beforeAll } from 'vitest';

import {
	calculateObjectSRI,
	calculateDataSRI,
	verifySRIFromObject,
	sriToSubtleAlgorithm,
	subtleToSriAlgorithm,
	sriAlgorithm,
	SubtleAlgorithm,
} from './sri';

const ALGORITHMS = Object.entries(sriToSubtleAlgorithm) as [
	sriAlgorithm,
	SubtleAlgorithm,
][];

function mockDigestFromString(str: string): ArrayBuffer {
	const encoder = new TextEncoder();
	return encoder.encode(str).buffer;
}

function mockBtoa() {
	(globalThis as any).btoa = (input: string) =>
		Buffer.from(input, 'binary').toString('base64');
}

function createMockSubtle(expectedDigest: ArrayBuffer) {
	return {
		digest: vi.fn().mockResolvedValue(expectedDigest),
	} as unknown as SubtleCrypto;
}

describe('sriUtils', () => {
	beforeAll(() => {
		mockBtoa();
	});

	describe('algorithm mappings', () => {
		it('sri -> subtle mapping', () => {
			expect(sriToSubtleAlgorithm.sha256).toBe('SHA-256');
			expect(sriToSubtleAlgorithm.sha384).toBe('SHA-384');
			expect(sriToSubtleAlgorithm.sha512).toBe('SHA-512');
		});

		it('subtle -> sri mapping', () => {
			expect(subtleToSriAlgorithm['SHA-256']).toBe('sha256');
			expect(subtleToSriAlgorithm['SHA-384']).toBe('sha384');
			expect(subtleToSriAlgorithm['SHA-512']).toBe('sha512');
		});
	});

	describe('calculateDataSRI', () => {
		it('returns SRI string with correct prefix', async () => {
			const subtle = createMockSubtle(mockDigestFromString('hello'));

			const result = await calculateDataSRI(
				subtle,
				new TextEncoder().encode('test'),
				'SHA-256'
			);

			expect(result.startsWith('sha256-')).toBe(true);
			expect(subtle.digest).toHaveBeenCalledWith(
				'SHA-256',
				expect.any(Uint8Array)
			);
		});

		it('produces different hashes for different input', async () => {
			const subtleA = createMockSubtle(mockDigestFromString('a'));
			const subtleB = createMockSubtle(mockDigestFromString('b'));

			const r1 = await calculateDataSRI(
				subtleA,
				new TextEncoder().encode('a'),
				'SHA-256'
			);

			const r2 = await calculateDataSRI(
				subtleB,
				new TextEncoder().encode('b'),
				'SHA-256'
			);

			expect(r1).not.toBe(r2);
		});

		it.each(
			Object.entries(sriToSubtleAlgorithm) as Array<
				[sriAlgorithm, SubtleAlgorithm]
			>
		)('supports %s algorithm', async (sriAlgo, subtleAlgo) => {
			const subtle = createMockSubtle(mockDigestFromString('test'));

			const result = await calculateDataSRI(
				subtle,
				new TextEncoder().encode('data'),
				subtleAlgo
			);

			expect(result.startsWith(`${sriAlgo}-`)).toBe(true);

			expect(subtle.digest).toHaveBeenCalledWith(
				subtleAlgo,
				expect.any(Uint8Array)
			);
		});
	});

	describe('calculateObjectSRI', () => {
		it('hashes JSON stringified object', async () => {
			const obj = { a: 1, b: 'test' };

			const subtle = createMockSubtle(
				mockDigestFromString(JSON.stringify(obj))
			);

			const result = await calculateObjectSRI(subtle, obj);

			expect(result.startsWith('sha256-')).toBe(true);
			expect(subtle.digest).toHaveBeenCalled();
		});

		it('same object → same SRI', async () => {
			const obj1 = { a: 1, b: 2 };
			const obj2 = { a: 1, b: 2 };

			const subtle = createMockSubtle(mockDigestFromString('same'));

			const r1 = await calculateObjectSRI(subtle, obj1);
			const r2 = await calculateObjectSRI(subtle, obj2);

			expect(r1).toBe(r2);
		});

		it.each(
			Object.entries(sriToSubtleAlgorithm) as Array<
				[sriAlgorithm, SubtleAlgorithm]
			>
		)('supports %s algorithm', async (sriAlgo, subtleAlgo) => {
			const obj = { value: 123 };

			const subtle = createMockSubtle(
				mockDigestFromString(JSON.stringify(obj))
			);

			const result = await calculateObjectSRI(subtle, obj, subtleAlgo);

			expect(result.startsWith(`${sriAlgo}-`)).toBe(true);

			expect(subtle.digest).toHaveBeenCalledWith(
				subtleAlgo,
				expect.any(Uint8Array)
			);
		});
	});

	describe('verifySRIFromObject', () => {
		it('returns true when integrity matches', async () => {
			const obj = { x: 42 };

			const subtle = createMockSubtle(
				mockDigestFromString(JSON.stringify(obj))
			);

			const sri = await calculateObjectSRI(subtle, obj);

			const result = await verifySRIFromObject(subtle, obj, sri);

			expect(result).toBe(true);
		});

		it('returns false when integrity does not match', async () => {
			const subtle = createMockSubtle(mockDigestFromString('x'));

			const result = await verifySRIFromObject(
				subtle,
				{ a: 1 },
				'sha256-wronghash'
			);

			expect(result).toBe(false);
		});

		it('throws on invalid integrity format', async () => {
			const subtle = createMockSubtle(mockDigestFromString('x'));

			await expect(
				verifySRIFromObject(subtle, { a: 1 }, 'invalidformat')
			).rejects.toThrow('Invalid integrity string format');
		});

		it('throws on unsupported algorithm', async () => {
			const subtle = createMockSubtle(mockDigestFromString('x'));

			await expect(
				verifySRIFromObject(subtle, { a: 1 }, 'md5-abc123')
			).rejects.toThrow('Unsupported algorithm');
		});
	});
});
