// Implementation of https://www.ietf.org/archive/id/draft-ietf-jose-json-web-proof-09.html
// and https://www.ietf.org/archive/id/draft-ietf-jose-json-proof-algorithms-09.html

import { JWK } from "jose";

import { getCipherSuite, PointG1, PointG2 } from "../bbs";
import { concat, fromBase64Url, I2OSP, OS2IP, toBase64Url, toU8 } from "../utils/util";


/** https://www.ietf.org/archive/id/draft-ietf-jose-json-proof-algorithms-09.html#name-bbs-using-sha-256-algorithm */
const ALG_IETF_BBS = 'BBS';
const ALG_SPLIT_BBS = 'experimental/SplitBBSv2.1';
const CRV_BLS12381G1 = 'BLS12381G1';
const CRV_BLS12381G2 = 'BLS12381G2';
type CRV_BLS12_381 = 'BLS12381G1' | 'BLS12381G2';

type JwkBlsPublic = JWK & { kty: "EC", alg: any, crv: CRV_BLS12_381, x: any, y: any };
type JwkBlsPrivate = JwkBlsPublic & { d: any };

/** Base64url-encoded binary string or raw binary data */
type JoseBytes = string | BufferSource;

type JwpHeader = {
	alg: string,
	kid?: string,
	typ?: string,
	crit?: string[],
	proof_key?: JWK,
	presentation_key?: JWK,
	iss?: string,
	aud?: string,
	nonce?: string | string[],
	[key: string]: any,
}

type IssuedJwp = {
	header: JwpHeader,
	payloads: BufferSource[],
	proof: BufferSource[],
}

type PresentedJwp = {
	presentationHeader: JwpHeader,
	issuerHeader: JwpHeader,
	payloads: (BufferSource | null)[],
	proof: BufferSource[],
}

function toBase64u(data: JoseBytes | JwpHeader): string {
	if (typeof data === 'string') {
		return data;
	} else if ("byteLength" in data && !("alg" in data)) {
		if (data.byteLength === 0) {
			return '_';
		} else {
			return toBase64Url(data);
		}
	} else {
		return toBase64u(new TextEncoder().encode(JSON.stringify(data)));
	}
}

function fromBase64u(data: string): BufferSource | null {
	if (data === '') {
		return null;
	} else if (data === '_') {
		return new Uint8Array([]);
	} else {
		return fromBase64Url(data);
	}
}

function assertJwkPublic(jwk: JWK, crv: CRV_BLS12_381, alg: string): jwk is JwkBlsPublic {
	if (jwk.kty !== "EC") {
		throw new Error(`Invalid key: wrong kty: expected EC, was: ${jwk.kty}`, { cause: { jwk } });
	}
	if (jwk.alg && jwk.alg !== alg) {
		throw new Error(`Invalid key: wrong alg: expected ${alg}, was: ${jwk.alg}`, { cause: { jwk } });
	}
	if (jwk.crv !== crv) {
		throw new Error(`Invalid key: wrong crv: expected ${crv}, was: ${jwk.crv}`, { cause: { jwk } });
	}
	if (!jwk.x) {
		throw new Error('Invalid key: missing x', { cause: { jwk } });
	}
	if (!jwk.y) {
		throw new Error('Invalid key: missing y', { cause: { jwk } });
	}

	return true;
}

function assertJwkPrivate(jwk: JWK, crv: CRV_BLS12_381, alg: string): jwk is JwkBlsPrivate {
	assertJwkPublic(jwk, crv, alg);

	if (!jwk.d) {
		throw new Error('Invalid private key: missing d', { cause: { jwk } });
	}

	return true;
}

export function importPrivateJwk(jwk: JWK, crv: CRV_BLS12_381, alg: string): bigint {
	if (!assertJwkPrivate(jwk, crv, alg)) {
		throw new Error('Invalid private key', { cause: { jwk } });
	}
	return OS2IP(fromBase64Url(jwk.d));
}

export function importIssuerPublicJwk(jwk: JWK, alg: string): BufferSource {
	if (!assertJwkPublic(jwk, CRV_BLS12381G2, alg)) {
		throw new Error('Invalid issuer public key', { cause: { jwk } });
	}

	const { params: { curves: { G2, fields: { Fp2 } } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const xBytes = fromBase64Url(jwk.x);
	const yBytes = fromBase64Url(jwk.y);
	// Fp2.toBytes emits coefficients in order c0, c1, ... cm while draft-ietf-lwig-curve-representations-23 uses order cm, ..., c1, c0
	const Q = G2.Point.fromAffine({
		x: Fp2.create({
			c1: OS2IP(xBytes.slice(0, xBytes.length / 2)),
			c0: OS2IP(xBytes.slice(xBytes.length / 2)),
		}),
		y: Fp2.create({
			c1: OS2IP(yBytes.slice(0, yBytes.length / 2)),
			c0: OS2IP(yBytes.slice(yBytes.length / 2)),
		}),
	});
	Q.assertValidity();
	return Q.toBytes();
}

export function importHolderPublicJwk(jwk: JWK, alg: string): PointG1 {
	if (!assertJwkPublic(jwk, CRV_BLS12381G1, alg)) {
		throw new Error('Invalid holder public key', { cause: { jwk } });
	}
	const { params: { curves: { G1, fields: { Fp } } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');

	const x = Fp.fromBytes(fromBase64Url(jwk.x));
	const y = Fp.fromBytes(fromBase64Url(jwk.y));
	return G1.Point.fromAffine({ x, y });
}

export function exportIssuerPublicJwk(pk: PointG2, alg: string): JwkBlsPublic {
	const { params: { curves: { fields: { Fp } } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const pkAff = pk.toAffine();
	return {
		kty: 'EC',
		crv: CRV_BLS12381G2,
		alg,
		// Fp2.toBytes emits coefficients in order c0, c1, ... cm while draft-ietf-lwig-curve-representations-23 uses order cm, ..., c1, c0
		x: toBase64Url(concat(Fp.toBytes(pkAff.x.c1), Fp.toBytes(pkAff.x.c0))),
		y: toBase64Url(concat(Fp.toBytes(pkAff.y.c1), Fp.toBytes(pkAff.y.c0))),
	};
}

export function exportIssuerPrivateJwk(sk: bigint, alg: string): JwkBlsPrivate {
	const { params: { curves: { G2, fields: { Fr } } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	return {
		...exportIssuerPublicJwk(G2.Point.BASE.multiply(sk), alg),
		d: toBase64Url(Fr.toBytes(sk)),
	};
}

export function exportHolderPublicJwk(pk: PointG1, alg: string): JwkBlsPublic {
	const { params: { curves: { fields: { Fp } } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const pkAff = pk.toAffine();
	return {
		kty: 'EC',
		crv: CRV_BLS12381G1,
		alg,
		x: toBase64Url(Fp.toBytes(pkAff.x)),
		y: toBase64Url(Fp.toBytes(pkAff.y)),
	};
}

export function exportHolderPrivateJwk(sk: bigint, alg: string): JwkBlsPrivate {
	const { params: { curves: { G1, fields: { Fr } } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	return {
		...exportHolderPublicJwk(G1.Point.BASE.multiply(sk), alg),
		d: toBase64Url(Fr.toBytes(sk)),
	};
}

export function parseIssuedJwp(jwp: string): {
	raw: { header: BufferSource, payloads: BufferSource[], proof: BufferSource[] },
	parsed: IssuedJwp,
} {
	const components = jwp.split(".");
	if (components.length !== 3) {
		throw new Error(`Invalid issued JWP: expected 3 .-separated components, found ${components.length}`, { cause: { jwp, components } });
	}
	const [jwpHeader, jwpPayloads, jwpProof] = components;
	const rawHeader = fromBase64u(jwpHeader);
	if (rawHeader === null) {
		throw new Error("Missing issuer header", { cause: { jwp } });
	}
	const payloads = jwpPayloads === '' ? [] : jwpPayloads.split("~").map(fromBase64u).map(p => {
		if (p === null) {
			throw new Error("Issued payload must not be null", { cause: { jwp } });
		} else {
			return p;
		}
	});
	const proof = jwpProof === '' ? [] : jwpProof.split("~").map(fromBase64u).map(p => {
		if (p === null) {
			throw new Error("Issuer proof component must not be null", { cause: { jwp } });
		} else {
			return p;
		}
	});
	return {
		raw: {
			header: rawHeader,
			payloads,
			proof,
		},
		parsed: {
			header: JSON.parse(new TextDecoder().decode(rawHeader)),
			payloads,
			proof,
		}
	};
}

export function parsePresentedJwp(jwp: string): {
	raw: { presentationHeader: BufferSource, issuerHeader: BufferSource, payloads: (BufferSource | null)[], proof: BufferSource[] },
	parsed: PresentedJwp,
} {
	const components = jwp.split(".");
	if (components.length !== 4) {
		throw new Error(`Invalid issued JWP: expected 4 .-separated components, found ${components.length}`, { cause: { jwp, components } });
	}
	const [jwpPresentationHeader, jwpIssuerHeader, jwpPayloads, jwpProof] = components;
	const rawPresentationHeader = fromBase64u(jwpPresentationHeader);
	const rawIssuerHeader = fromBase64u(jwpIssuerHeader);
	if (rawPresentationHeader === null) {
		throw new Error("Missing presentation header", { cause: { jwp } });
	}
	if (rawIssuerHeader === null) {
		throw new Error("Missing issuer header", { cause: { jwp } });
	}
	const presentationHeader = JSON.parse(new TextDecoder().decode(rawPresentationHeader));
	const issuerHeader = JSON.parse(new TextDecoder().decode(rawIssuerHeader));
	const payloads = jwpPayloads.split("~").map(fromBase64u);
	const proof = jwpProof === '' ? [] : jwpProof.split("~").map(fromBase64u).map(p => {
		if (p === null) {
			throw new Error("Presentation proof component must not be null", { cause: { jwp } });
		} else {
			return p;
		}
	});
	return {
		raw: {
			presentationHeader: rawPresentationHeader,
			issuerHeader: rawIssuerHeader,
			payloads,
			proof,
		},
		parsed: {
			presentationHeader,
			issuerHeader,
			payloads,
			proof,
		},
	};
}

/** Base64url-encode (if needed) and concatenate `components` using `.` as the separator. */
function jwpConcat(...components: JoseBytes[]): string {
	return components.map(toBase64u).join(".");
}

/** Base64url-encode (if needed) and concatenate `components` using `~` as the separator. */
function jwpConcatPayloads(...components: JoseBytes[]): string {
	return components.map(toBase64u).join("~");
}

export function assembleIssuedJwp(header: JwpHeader, payloads: JoseBytes[], proof: JoseBytes[]): string {
	return jwpConcat(toBase64u(header), jwpConcatPayloads(...payloads), jwpConcatPayloads(...proof));
}

export function assemblePresentationJwp(issuedJwp: string, presentationHeader: JwpHeader, disclosedIndexes: number[], proof: JoseBytes[]): string {
	const [issuerHeader, payloads, _issuerProof] = issuedJwp.split(".");
	const disclosedSet = new Set(disclosedIndexes);
	return jwpConcat(
		toBase64u(presentationHeader),
		issuerHeader,
		jwpConcatPayloads(...payloads.split("~").map((payload, i) => disclosedSet.has(i) ? payload : '')),
		jwpConcatPayloads(...proof),
	);
}

export async function issueBbs(SK: bigint, PK: BufferSource, header: JwpHeader, payloads: BufferSource[]): Promise<string> {
	if (payloads.length === 0) {
		throw new Error('Cannot issue JWP with zero payloads');
	}
	const { Sign } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const jwpHeader = {
		...header,
		alg: ALG_IETF_BBS,
	};
	const proof = await Sign(SK, PK, new TextEncoder().encode(JSON.stringify(jwpHeader)), payloads);
	return assembleIssuedJwp(header, payloads, [proof]);
}

export async function issueSplitBbs(
	issuerKey: JWK,
	header: JwpHeader,
	dpk: JWK,
	payloads: BufferSource[],
): Promise<string> {
	if (payloads.length === 0) {
		throw new Error('Cannot issue JWP with zero payloads');
	}

	const { SkToPk, SplitSign, params: { curves: { G1 } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const SK = importPrivateJwk(issuerKey, CRV_BLS12381G2, ALG_SPLIT_BBS);
	const PK = SkToPk(SK);
	const dpkPoint = importHolderPublicJwk(dpk, ALG_SPLIT_BBS);

	const jwpHeader = {
		...header,
		alg: ALG_SPLIT_BBS,
	};
	const proof = await SplitSign(
		SK,
		PK,
		new TextEncoder().encode(JSON.stringify(jwpHeader)),
		dpkPoint,
		G1.Point.BASE,
		payloads,
	);
	return assembleIssuedJwp(header, payloads, [proof, dpkPoint.toBytes()]);
}

export async function confirm(PK: JWK, issuedJwp: string): Promise<true> {
	const { raw: { header }, parsed: { header: { alg }, payloads, proof } } = parseIssuedJwp(issuedJwp);
	switch (alg) {
		case ALG_IETF_BBS:
			{
				// https://www.ietf.org/archive/id/draft-ietf-jose-json-proof-algorithms-09.html#name-bbs-using-sha-256-algorithm
				const { Verify } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
				const valid = await Verify(importIssuerPublicJwk(PK, ALG_IETF_BBS), proof[0], header, payloads);
				return valid;
			}

		case ALG_SPLIT_BBS:
			{
				const { SplitVerify, params: { curves: { G1 } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
				const [signature, dpkBytes] = proof;
				const dpkPoint = G1.Point.fromBytes(toU8(dpkBytes));
				const valid = await SplitVerify(importIssuerPublicJwk(PK, ALG_SPLIT_BBS), signature, header, dpkPoint, G1.Point.BASE, payloads);
				return valid;
			}

		default:
			throw new Error(`Unknown JPA: ${alg}`, { cause: { jwp: issuedJwp, alg } });
	}
}

export async function presentBbs(
	PK: BufferSource,
	issuedJwp: string,
	presentationHeader: JwpHeader,
	discloseIndexes: number[],
): Promise<string> {
	const { raw: { header }, parsed: { payloads, proof: [signature] } } = parseIssuedJwp(issuedJwp);
	const { ProofGen } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const encodedPresentationHeader = new TextEncoder().encode(JSON.stringify(presentationHeader));
	const proof = await ProofGen(
		PK,
		signature,
		header,
		encodedPresentationHeader,
		payloads,
		discloseIndexes,
	);
	return assemblePresentationJwp(issuedJwp, presentationHeader, discloseIndexes, [proof]);
}

export async function presentSplitBbs(
	issuerKey: JWK,
	issuedJwp: string,
	presentationHeader: JwpHeader,
	discloseIndexes: number[],
	deviceSign: (T2bar: PointG1, c_host: bigint) => Promise<BufferSource>,
): Promise<string> {
	if (presentationHeader.alg !== ALG_SPLIT_BBS) {
		throw new Error(`Bad alg in presentation header: expected ${ALG_SPLIT_BBS}, was: ${presentationHeader.alg}`, { cause: { presentationHeader } });
	}

	const { raw: { header }, parsed: { payloads: payloads, proof: [signature, dpk] } } = parseIssuedJwp(issuedJwp);
	const { SplitProofGenBegin, SplitProofGenFinish, params: { curves: { G1 } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const encodedPresentationHeader = new TextEncoder().encode(JSON.stringify({
		...presentationHeader,
		alg: ALG_SPLIT_BBS,
	}));
	const PK = importIssuerPublicJwk(issuerKey, ALG_SPLIT_BBS);
	const dpkPoint = G1.Point.fromBytes(toU8(dpk));
	const [init_res, begin_res, T2bar, c_host] = await SplitProofGenBegin(
		PK,
		signature,
		header,
		encodedPresentationHeader,
		dpkPoint,
		G1.Point.BASE,
		payloads,
		discloseIndexes,
	);
	const deviceResp = await deviceSign(T2bar, c_host);
	const [p, sa_dpk, n] = await SplitProofGenFinish([init_res, begin_res, T2bar, c_host], deviceResp);
	return assemblePresentationJwp(issuedJwp, presentationHeader, discloseIndexes, [p, I2OSP(sa_dpk, 32), n]);
}

export async function verify(PK: BufferSource, presentedJwp: string): Promise<true> {
	const {
		raw: { presentationHeader, issuerHeader },
		parsed: { issuerHeader: { alg }, payloads, proof },
	} = parsePresentedJwp(presentedJwp);
	switch (alg) {
		case ALG_IETF_BBS:
			// https://www.ietf.org/archive/id/draft-ietf-jose-json-proof-algorithms-09.html#name-bbs-using-sha-256-algorithm
			{
				const { ProofVerify } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
				const valid = await ProofVerify(
					PK,
					proof[0],
					issuerHeader,
					presentationHeader,
					payloads.filter(p => p !== null),
					payloads.map((p, i) => p === null ? null : i).filter(i => i !== null),
				);
				return valid;
			}

		case ALG_SPLIT_BBS:
			{
				const { SplitProofVerify, params: { curves: { G1 } } } = getCipherSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
				const [p, sa_dpk, n] = proof;
				const valid = await SplitProofVerify(
					PK,
					[p, OS2IP(sa_dpk), n],
					G1.Point.BASE,
					issuerHeader,
					presentationHeader,
					payloads.filter(p => p !== null),
					payloads.map((p, i) => p === null ? null : i).filter(i => i !== null),
				);
				return valid;
			}

		default:
			throw new Error(`Unknown JPA: ${alg}`, { cause: { jwp: presentedJwp, alg } });
	}
}
