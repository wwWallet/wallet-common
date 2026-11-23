import { SDJwt } from '@sd-jwt/core';
import type { JWK } from 'jose';

const encoder = new TextEncoder();

/**
 * Returns the holder's public key (`cnf.jwk`) from an SD-JWT, or `null` when it has none.
 * Throws when the SD-JWT can't be decoded.
 */
export async function getSdJwtHolderPublicKey(
	rawCredential: string,
	subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<JWK | null> {
	const hasher = (data: string | ArrayBuffer, alg: string) => {
		const bytes = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
		return subtle.digest(alg, bytes).then((v) => new Uint8Array(v));
	};

	const sdJwt = await SDJwt.fromEncode(rawCredential, hasher);
	const payload = sdJwt.jwt?.payload as { cnf?: { jwk?: JWK } } | undefined;
	return payload?.cnf?.jwk ?? null;
}
