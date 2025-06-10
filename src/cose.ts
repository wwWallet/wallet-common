import * as cbor from 'cbor-web';

// ARKG-pub https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-cose-key-types-registration
export const COSE_KTY_ARKG_PUB = -65537;
export type COSE_KTY_ARKG_PUB = typeof COSE_KTY_ARKG_PUB; // eslint-disable-line @typescript-eslint/no-redeclare

// ARKG-derived https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-cose-key-types-registration
export const COSE_KTY_ARKG_DERIVED = -65538;
export type COSE_KTY_ARKG_DERIVED = typeof COSE_KTY_ARKG_DERIVED; // eslint-disable-line @typescript-eslint/no-redeclare

// ESP256-ARKG (no spec yet)
export const COSE_ALG_ESP256_ARKG = -65539;
export type COSE_ALG_ESP256_ARKG = typeof COSE_ALG_ESP256_ARKG; // eslint-disable-line @typescript-eslint/no-redeclare

// ARKG-P256 https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-08.html#name-cose-key-type-arkg-public-s
export const COSE_ALG_ARKG_P256 = -65700;
export type COSE_ALG_ARKG_P256 = typeof COSE_ALG_ARKG_P256; // eslint-disable-line @typescript-eslint/no-redeclare


export type ParsedCOSEKey = {
	kty: number | string,
	kid?: Uint8Array,
	alg?: COSEAlgorithmIdentifier,
	[name: string]: any,
};

export type ParsedCOSEKeyEc2Public = ParsedCOSEKey & {
	kty: 2,
	kid?: Uint8Array,
	alg?: COSEAlgorithmIdentifier,
	crv: number,
	x: Uint8Array,
	y: Uint8Array,
};

export type ParsedCOSEKeyArkgPubSeed = ParsedCOSEKey & {
	kty: COSE_KTY_ARKG_PUB,
	alg: COSEAlgorithmIdentifier,
	pkBl: ParsedCOSEKey,
	pkKem: ParsedCOSEKey,
};

export type ParsedCOSEKeyRef = {
	kty: number | string,
	kid: Uint8Array,
	alg?: COSEAlgorithmIdentifier,
	[name: string]: any,
};

export type ParsedCOSEKeyRefArkgDerivedBase = ParsedCOSEKeyRef & {
	kty: COSE_KTY_ARKG_DERIVED,
};

export type ParsedCOSEKeyRefArkgDerived = ParsedCOSEKeyRefArkgDerivedBase & {
	kh: Uint8Array,
	info: Uint8Array,
}

export async function importCosePublicKey(cose: cbor.Map): Promise<CryptoKey> {
	const coseKey = parseCoseKeyEc2Public(cose);
	const [algorithm, keyUsages] = getEcKeyImportParams(coseKey);
	const rawBytes = new Uint8Array([
		0x04,
		...new Uint8Array(Math.max(0, 32 - coseKey.x.length)),
		...coseKey.x,
		...new Uint8Array(Math.max(0, 32 - coseKey.y.length)),
		...coseKey.y,
	]);
	return await crypto.subtle.importKey("raw", rawBytes, algorithm, true, keyUsages);
}

function getEcKeyImportParams(cose: ParsedCOSEKeyEc2Public): [EcKeyImportParams, KeyUsage[]] {
	const { alg, crv } = cose;
	switch (alg) {
		case -7: // ES256
			switch (crv) {
				case 1: // P-256
					return [{ name: "ECDSA", namedCurve: "P-256" }, ["verify"]];
				default:
					throw new Error(`Unsupported COSE elliptic curve: ${crv}`, { cause: { crv } })
			}

		case -25: // ECDH-ES + HKDF-256
			switch (crv) {
				case 1: // P-256
					return [{ name: "ECDH", namedCurve: "P-256" }, ["deriveBits", "deriveKey"]];

				default:
					throw new Error(`Unsupported COSE elliptic curve: ${crv}`, { cause: { crv } })
			}

		default:
			throw new Error(`Unsupported COSE algorithm: ${alg}`, { cause: { alg } })
	}
}

export function parseCoseKeyEc2Public(cose: cbor.Map): ParsedCOSEKeyEc2Public {
	const kty = cose.get(1);
	switch (kty) {

		case 2: // EC2
			const alg = cose.get(3);
			switch (alg) {

				case -7: // ES256
				case -9: // ESP256
				case -25: // ECDH-ES w/ HKDF
					const crv = cose.get(-1);
					switch (crv) {

						case 1: // P-256
							const x = cose.get(-2);
							const y = cose.get(-3);
							if (x && y) {
								if (!(x instanceof Uint8Array)) {
									throw new Error(
										`Incorrect type of "x (-2)" attribute of EC2 COSE_Key: ${typeof x} ${x}`,
										{ cause: { x } },
									);
								}
								if (!(y instanceof Uint8Array)) {
									throw new Error(
										`Incorrect type of "y (-3)" attribute of EC2 COSE_Key: ${typeof y} ${y}`,
										{ cause: { y } },
									);
								}
								return { kty, alg, crv, x, y };
							} else {
								throw new Error(`Invalid COSE EC2 ES256 or ECDH key: missing x or y`, { cause: { x, y } });
							}

						default:
							throw new Error(`Unsupported COSE elliptic curve: ${crv}`, { cause: { crv } })
					}

				default:
					throw new Error(`Unsupported COSE algorithm: ${alg}`, { cause: { alg } })
			}

		default:
			throw new Error(`Unsupported COSE key type: ${kty}`, { cause: { kty } });
	}
}

export function parseCoseKeyArkgPubSeed(cose: cbor.Map): ParsedCOSEKeyArkgPubSeed {
	const kty = cose.get(1);
	switch (kty) {
		case COSE_KTY_ARKG_PUB:
			const kid = cose.get(2);
			if (!(kid instanceof Uint8Array)) {
				throw new Error(
					`Incorrect type of "kid (2)" attribute of ARKG-pub COSE_Key: ${typeof kid} ${kid}`,
					{ cause: { kid } },
				);
			}

			let alg = cose.get(3);
			switch (alg) {
				case COSE_ALG_ESP256_ARKG:
					console.warn(`WARNING: Wrong alg (3) value in ARKG-pub COSE_Key: ${alg}; should probably be ${COSE_ALG_ARKG_P256}`);
					alg = COSE_ALG_ARKG_P256;
					break;

				case COSE_ALG_ARKG_P256:
					// OK; do nothing
					break;

				default:
					throw new Error("Unsupported alg (3) in ARKG-pub COSE_Key: " + alg)
			}

			const pkBl = parseCoseKeyEc2Public(cose.get(-1));
			const pkKem = parseCoseKeyEc2Public(cose.get(-2));
			return { kty, kid, pkBl, pkKem, alg };

		default:
			throw new Error(`Unsupported COSE key type: ${kty}`, { cause: { kty } });
	}
}

export function encodeCoseKeyRefArkgDerived(keyRef: ParsedCOSEKeyRefArkgDerived): ArrayBuffer {
	return new Uint8Array(cbor.encodeCanonical(new cbor.Map([ // Can't use object literal because that turns integer keys into strings
		[1, keyRef.kty],
		[2, keyRef.kid.buffer],
		[3, keyRef.alg],
		[-1, keyRef.kh.buffer],
		[-2, keyRef.info.buffer],
	]))).buffer;
}
