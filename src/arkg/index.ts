/// Implementation of ARKG
/// https://datatracker.ietf.org/doc/draft-bradleylundberg-cfrg-arkg/09/

import * as ec from './ec';
import * as hash_to_curve from './hash_to_curve';
import { byteArrayEquals, concat, I2OSP, toU8 } from '../utils/util';
import { COSE_ALG_ARKG_P256, ParsedCOSEKeyArkgPubSeed, ParsedCOSEKeyEc2Public } from '../cose';


const CTX_MAX_LEN = 64;

type DeriveKeypairFunction<PublicKey, PrivateKey> = (
	(ikm: BufferSource) => Promise<[PublicKey, PrivateKey]>
);

type BlPrfFunction<BlindingFactor> = (
	(ikm_tau: BufferSource, ctx: BufferSource) => Promise<BlindingFactor>
);
type BlBlindKeyFunction<BaseKey, BlindingFactor, BlindedKey> = (
	(key: BaseKey, tau: BlindingFactor) => Promise<BlindedKey>
);
type BlScheme<PublicKey, PrivateKey, BlindingFactor, DerivedPublicKey, DerivedPrivateKey> = {
	deriveKeypair: DeriveKeypairFunction<PublicKey, PrivateKey>,
	prf: BlPrfFunction<BlindingFactor>,
	blindPublicKey: BlBlindKeyFunction<PublicKey, BlindingFactor, DerivedPublicKey>,
	blindPrivateKey: BlBlindKeyFunction<PrivateKey, BlindingFactor, DerivedPrivateKey>,
}

type KemEncapsFunction<PublicKey> = (
	(pk: PublicKey, ikm: BufferSource, ctx: BufferSource) => Promise<[ArrayBuffer, ArrayBuffer]>
);
type KemDecapsFunction<PrivateKey> = (
	(sk: PrivateKey, c: BufferSource, ctx: BufferSource) => Promise<ArrayBuffer>
);
type KemScheme<PublicKey, PrivateKey> = {
	deriveKeypair: DeriveKeypairFunction<PublicKey, PrivateKey>,
	encaps: KemEncapsFunction<PublicKey>,
	decaps: KemDecapsFunction<PrivateKey>,
}

export type ArkgPublicSeed<BlPublicKey, KemPublicKey> = {
	pk_bl: BlPublicKey,
	pk_kem: KemPublicKey,
}
type ArkgPrivateSeed<BlPrivateKey, KemPrivateKey> = {
	sk_bl: BlPrivateKey,
	sk_kem: KemPrivateKey,
}

type ArkgDeriveSeedFunction<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey> = (
	(ikm_bl: BufferSource, ikm_kem: BufferSource) => Promise<[ArkgPublicSeed<BlPublicKey, KemPublicKey>, ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>]>
);
type ArkgDerivePublicKeyFunction<BlPublicKey, KemPublicKey, DerivedPublicKey> = (
	(
		seed_pk: ArkgPublicSeed<BlPublicKey, KemPublicKey>,
		ikm: BufferSource,
		ctx: BufferSource,
	) => Promise<[DerivedPublicKey, ArrayBuffer]>
);
type ArkgDerivePrivateKeyFunction<BlPrivateKey, KemPrivateKey, DerivedPrivateKey> = (
	(
		seed_prik: ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>,
		kh: BufferSource,
		ctx: BufferSource,
	) => Promise<DerivedPrivateKey>
);
type ArkgInstance<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey, DerivedPublicKey, DerivedPrivateKey> = {
	/** @see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-the-function-arkg-derive-se */
	deriveSeed: ArkgDeriveSeedFunction<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey>,

	/** @see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-the-function-arkg-derive-pu */
	derivePublicKey: ArkgDerivePublicKeyFunction<BlPublicKey, KemPublicKey, DerivedPublicKey>,

	/** @see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-the-function-arkg-derive-pr */
	derivePrivateKey: ArkgDerivePrivateKeyFunction<BlPrivateKey, KemPrivateKey, DerivedPrivateKey>,
}


/** @see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-the-asynchronous-remote-key */
function arkg<BlPublicKey, BlPrivateKey, BlindingFactor, KemPublicKey, KemPrivateKey, DerivedPublicKey, DerivedPrivateKey>(
	bl: BlScheme<BlPublicKey, BlPrivateKey, BlindingFactor, DerivedPublicKey, DerivedPrivateKey>,
	kem: KemScheme<KemPublicKey, KemPrivateKey>,
): ArkgInstance<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey, DerivedPublicKey, DerivedPrivateKey> {
	return {
		deriveSeed: async (ikm_bl: BufferSource, ikm_kem): Promise<[ArkgPublicSeed<BlPublicKey, KemPublicKey>, ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>]> => {
			const [pk_bl, sk_bl] = await bl.deriveKeypair(ikm_bl);
			const [pk_kem, sk_kem] = await kem.deriveKeypair(ikm_kem);
			const pk = { pk_bl, pk_kem };
			const sk = { sk_bl, sk_kem };
			return [pk, sk];
		},

		derivePublicKey: async (
			{ pk_bl, pk_kem }: ArkgPublicSeed<BlPublicKey, KemPublicKey>,
			ikm: BufferSource,
			ctx: BufferSource,
		): Promise<[DerivedPublicKey, ArrayBuffer]> => {
			if (ctx.byteLength > CTX_MAX_LEN) {
				throw new Error("ctx too long", { cause: { ctx, maxLength: CTX_MAX_LEN } });
			}

			const ctx_prime = concat(I2OSP(ctx.byteLength, 1), ctx);
			const ctx_kem = concat(new TextEncoder().encode('ARKG-Derive-Key-KEM.'), ctx_prime);
			const ctx_bl = concat(new TextEncoder().encode('ARKG-Derive-Key-BL.'), ctx_prime);
			const [ikm_tau, c] = await kem.encaps(pk_kem, ikm, ctx_kem);
			const tau = await bl.prf(ikm_tau, ctx_bl);
			const pk_prime = await bl.blindPublicKey(pk_bl, tau);
			const kh = c;
			return [pk_prime, kh];
		},

		derivePrivateKey: async (
			{ sk_bl, sk_kem }: ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>,
			kh: BufferSource,
			ctx: BufferSource,
		): Promise<DerivedPrivateKey> => {
			if (ctx.byteLength > CTX_MAX_LEN) {
				throw new Error("ctx too long", { cause: { ctx, maxLength: CTX_MAX_LEN } });
			}

			const ctx_prime = concat(I2OSP(ctx.byteLength, 1), ctx);
			const ctx_kem = concat(new TextEncoder().encode('ARKG-Derive-Key-KEM.'), ctx_prime);
			const ctx_bl = concat(new TextEncoder().encode('ARKG-Derive-Key-BL.'), ctx_prime);
			const ikm_tau = await kem.decaps(sk_kem, kh, ctx_kem);
			const tau = await bl.prf(ikm_tau, ctx_bl);
			const sk_prime = await bl.blindPrivateKey(sk_bl, tau);
			return sk_prime;
		}
	};
}

/** @see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-using-elliptic-curve-additi */
function arkgBlEcAdd(
	hashToCurveSuiteId: hash_to_curve.SuiteId,
	DST_ext: BufferSource,
): BlScheme<ec.Point, bigint, bigint, ec.Point, bigint> {
	const { suiteParams } = hash_to_curve.hashToCurve(hashToCurveSuiteId, concat(
		new TextEncoder().encode('ARKG-BL-EC.'),
		DST_ext,
	));
	const { curve: crv } = suiteParams;

	if (suiteParams.m !== 1) {
		throw new Error("Invalid argument: hash_to_crv_suite parameter m must equal 1");
	}

	const prf = async (ikm_tau: BufferSource, ctx: BufferSource): Promise<bigint> => {
		const DST_tau = concat(new TextEncoder().encode('ARKG-BL-EC.'), DST_ext, ctx);
		const { hashToScalarField } = hash_to_curve.hashToCurve(hashToCurveSuiteId, DST_tau);
		const [[tau]] = await hashToScalarField(ikm_tau, 1);
		return tau;
	};

	return {
		deriveKeypair: async (ikm: BufferSource): Promise<[ec.Point, bigint]> => {
			const DST_bl_sk = concat(new TextEncoder().encode('ARKG-BL-EC-KG.'), DST_ext);
			const { hashToScalarField } = hash_to_curve.hashToCurve(hashToCurveSuiteId, DST_bl_sk);
			const [[sk]] = await hashToScalarField(ikm, 1);
			const pk = ec.vartimeMul(crv, crv.generator, sk);
			return [pk, sk];
		},

		prf,

		blindPublicKey: async (pk: ec.Point, tau: bigint): Promise<ec.Point> => {
			const pk_tau = ec.vartimeAdd(crv, pk, ec.vartimeMul(crv, crv.generator, tau));
			return pk_tau;
		},

		blindPrivateKey: async (prik: bigint, tau: bigint): Promise<bigint> => {
			const sk_tau_tmp = (prik + tau) % crv.order;
			if (sk_tau_tmp === 0n) {
				throw new Error("Invalid secret key");
			}
			const sk_tau = sk_tau_tmp;
			return sk_tau;
		},
	};
}

/** @see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-using-hmac-to-adapt-a-kem-w */
function arkgHmacKem<PublicKey, PrivateKey>(
	hash: "SHA-256",
	DST_ext: BufferSource,
	SubKem: KemScheme<PublicKey, PrivateKey>,
): KemScheme<PublicKey, PrivateKey> {
	return {
		deriveKeypair: SubKem.deriveKeypair,

		encaps: async (pk: PublicKey, ikm: BufferSource, ctx: BufferSource): Promise<[ArrayBuffer, ArrayBuffer]> => {
			const ctx_sub = concat(new TextEncoder().encode('ARKG-KEM-HMAC.'), DST_ext, ctx);
			const [k_prime, c_prime] = await SubKem.encaps(pk, ikm, ctx_sub);

			const hkdf_ikm = await crypto.subtle.importKey("raw", k_prime, { name: "HKDF" }, false, ["deriveBits", "deriveKey"]);

			const mk = await crypto.subtle.deriveKey(
				{
					name: "HKDF",
					hash,
					salt: new Uint8Array([]),
					info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-mac.'), DST_ext, ctx),
				},
				hkdf_ikm,
				{ name: "HMAC", hash, length: 32*8 },
				false,
				["sign"],
			);
			const t = toU8(await crypto.subtle.sign("HMAC", mk, c_prime)).slice(0, 16);

			const k = await crypto.subtle.deriveBits(
				{
					name: "HKDF",
					hash,
					salt: new Uint8Array([]),
					info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-shared.'), DST_ext, ctx),
				},
				hkdf_ikm,
				k_prime.byteLength * 8,
			);
			const c = concat(t, c_prime);

			return [k, c];
		},

		decaps: async (sk: PrivateKey, c: BufferSource, ctx: BufferSource): Promise<ArrayBuffer> => {
			const c_u8 = toU8(c);
			const t = c_u8.slice(0, 16);
			const c_prime = c_u8.slice(16);
			const ctx_sub = concat(new TextEncoder().encode('ARKG-KEM-HMAC.'), DST_ext, ctx);
			const k_prime = await SubKem.decaps(sk, c_prime, ctx_sub);

			const ikm = await crypto.subtle.importKey("raw", k_prime, { name: "HKDF" }, false, ["deriveBits", "deriveKey"]);

			const mk = await crypto.subtle.deriveKey(
				{
					name: "HKDF",
					hash,
					salt: new Uint8Array([]),
					info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-mac.'), DST_ext, ctx),
				},
				ikm,
				{ name: "HMAC", hash, length: 32*8 },
				false,
				["sign"],
			);

			const t_prime = new Uint8Array(await crypto.subtle.sign("HMAC", mk, c_prime)).slice(0, 16);
			if (byteArrayEquals(t, t_prime)) {
				const k = await crypto.subtle.deriveBits(
					{
						name: "HKDF",
						hash,
						salt: new Uint8Array([]),
						info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-shared.'), DST_ext, ctx),
					},
					ikm,
					k_prime.byteLength * 8,
				);
				return k;

			} else {
				throw new Error("Invalid MAC");
			}
		},
	};
}

/** @see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-using-ecdh-as-the-kem */
function arkgEcdhKem(
	namedCurve: "P-256",
	hash: "SHA-256",
	hashToCurveSuiteId: hash_to_curve.SuiteId,
	DST_ext: BufferSource,
): KemScheme<CryptoKey, CryptoKey> {
	const [crv, L]: [ec.Curve, number] | [null, null] = (namedCurve === "P-256" ? [ec.curveSecp256r1(), 8 * 32] : [null, null]);
	if (crv === null) {
		throw new Error("Unknown curve: " + namedCurve);
	}

	const DST_aug = concat(new TextEncoder().encode('ARKG-ECDH.'), DST_ext);

	const deriveKeypair = async (ikm: BufferSource): Promise<[CryptoKey, CryptoKey]> => {
		const DST_kem_sk = concat(new TextEncoder().encode('ARKG-KEM-ECDH-KG.'), DST_aug);
		const { hashToScalarField } = hash_to_curve.hashToCurve(hashToCurveSuiteId, DST_kem_sk);
		const [[sk]] = await hashToScalarField(ikm, 1);
		const pk = ec.vartimeMul(crv, crv.generator, sk);
		return [
			await ec.publicKeyFromPoint("ECDH", namedCurve, pk),
			await ec.privateKeyFromScalar("ECDH", namedCurve, sk, true, ["deriveBits"]),
		];
	};

	return arkgHmacKem(hash, DST_aug, {
		deriveKeypair,

		encaps: async (pubk: CryptoKey, ikm: BufferSource, _ctx: BufferSource): Promise<[ArrayBuffer, ArrayBuffer]> => {
			const [pk_prime, sk_prime] = await deriveKeypair(ikm);
			const k = await crypto.subtle.deriveBits({ name: "ECDH", public: pubk }, sk_prime, L);
			const c = await crypto.subtle.exportKey("raw", pk_prime);
			return [k, c];
		},

		decaps: async (prik: CryptoKey, c: BufferSource, _ctx: BufferSource): Promise<ArrayBuffer> => {
			const pk_prime = await crypto.subtle.importKey("raw", c, { name: "ECDH", namedCurve }, true, []);
			const k = await crypto.subtle.deriveBits({ name: "ECDH", public: pk_prime }, prik, L);
			return k;
		},
	});
}

/**
	@see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-arkg-p256
	*/
export type EcInstanceId = (
	'ARKG-P256'
);

// Declare as factory functions instead of a global variable registry to prevent callers from overriding internal properties
const ecInstances: { [id in EcInstanceId]: () => ArkgInstance<ec.Point, bigint, CryptoKey, CryptoKey, ec.Point, bigint> } = {
	'ARKG-P256': () => arkg(
		arkgBlEcAdd("P256_XMD:SHA-256_SSWU_RO_", new TextEncoder().encode('ARKG-P256')),
		arkgEcdhKem("P-256", "SHA-256", "P256_XMD:SHA-256_SSWU_RO_", new TextEncoder().encode('ARKG-P256')),
	),
};

/**
	Instantiate an EC-based ARKG instance.

	@see https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-concrete-arkg-instantiation
	*/
export function getEcInstance(id: EcInstanceId): ArkgInstance<ec.Point, bigint, CryptoKey, CryptoKey, ec.Point, bigint> {
	return ecInstances[id]();
}

export function coseToInstanceId(coseId: COSEAlgorithmIdentifier): EcInstanceId | null {
	switch (coseId) {
		case COSE_ALG_ARKG_P256:
			return 'ARKG-P256';
		default:
			return null;
	}
}

export function getCoseEcInstance(coseId: COSEAlgorithmIdentifier): ArkgInstance<ec.Point, bigint, CryptoKey, CryptoKey, ec.Point, bigint> | null {
	const id = coseToInstanceId(coseId);
	return id ? getEcInstance(id) : null;
}

export async function ecPublicKeyFromCose(pk: ParsedCOSEKeyArkgPubSeed): Promise<ArkgPublicSeed<ec.Point, CryptoKey>> {
	switch (pk.alg) {
		case COSE_ALG_ARKG_P256:
			const crv = ec.curveSecp256r1();
			return {
				pk_bl: await ec.pointFromCosePublicKey(crv, pk.pkBl as ParsedCOSEKeyEc2Public),
				pk_kem: await ec.publicKeyFromPoint("ECDH", "P-256", await ec.pointFromCosePublicKey(crv, pk.pkKem as ParsedCOSEKeyEc2Public)),
			};

		default:
			throw new Error("Unsupported ARKG algorithm for COSE identifier: " + pk.alg);
	}
}
