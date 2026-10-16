import { describe, expect, it } from 'vitest';
import { generateECDHKeypair } from './ECDH-ES';

describe('generateECDHKeypair', () => {
	it('marks generated keys for ECDH-ES encryption', async () => {
		const keypair = await generateECDHKeypair();
		expect(keypair.publicKeyJwk.alg).toBe('ECDH-ES');
		expect(keypair.publicKeyJwk.use).toBe('enc');
		expect(keypair.privateKeyJwk.alg).toBe('ECDH-ES');
		expect(keypair.privateKeyJwk.use).toBe('enc');
		expect(keypair.publicKeyJwk.kid).toBe(keypair.privateKeyJwk.kid);
	});
});
