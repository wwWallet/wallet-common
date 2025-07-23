import { PointG1 } from "./bbs";
import { ALG_SPLIT_BBS, IssuedJwp, JwpHeader, parseJwp, PresentedJwp } from "./jwp";
import * as jwp from "./jwp";
import { fromBase64Url } from "./utils/util";

export type ClaimPath = (string | null | number)[];
export type ClaimsMetadata = { claims: { path: ClaimPath }[] };

export type JptComplexClaim = { path: ClaimPath, value: unknown };
export type JptClaims = {
	simple: Record<string, unknown>,
	complex: JptComplexClaim[],
};

export type IssuedJpt = {
	issuerHeader: JwpHeader,
	claims: JptClaims,
	proof: BufferSource[],
}

export type PresentedJpt = {
	presentationHeader: JwpHeader,
	issuerHeader: JwpHeader,
	claims: JptClaims,
	proof: BufferSource[],
}

function pathEquals(a: ClaimPath, b: ClaimPath): boolean {
	return (a === b) || ((a && b) && (a.length === b.length) && a.every((va, i) => va === b[i]));
}

export function extractPayloadsFromClaims(
	claims: { [key: string]: any },
	metadata: ClaimsMetadata,
): Uint8Array[] {
	return metadata.claims.map(claimMeta => {
		const claimValue = claimMeta.path.reduce(
			(values, pathComp) => {
				if (typeof pathComp === "string") {
					return values.flatMap(value => {
						if (typeof value === "object" && !(value instanceof Array)) {
							return pathComp in value ? [value[pathComp]] : [];
						} else {
							throw new Error(`Incorrect claim type at key ${pathComp}: expected object, was: ${typeof value} (array: ${value instanceof Array})`);
						}
					});
				} else if (typeof pathComp === "number") {
					return values.flatMap(value => {
						if (typeof value === "object" && value instanceof Array) {
							return pathComp < value.length ? [value[pathComp]] : [];
						} else {
							throw new Error(`Incorrect claim type at key ${pathComp}: expected array, was: ${typeof value} (array: ${value instanceof Array})`);
						}
					});
				} else if (pathComp === null) {
					return values.flatMap(value => {
						if (typeof value === "object" && value instanceof Array) {
							return value;
						} else {
							throw new Error(`Incorrect claim type at key ${pathComp}: expected array, was: ${typeof value} (array: ${value instanceof Array})`);
						}
					});
				} else {
					throw new Error(`Invalid claim path component: ${typeof pathComp} ${pathComp}`);
				}
			},
			[claims],
		);
		if (claimMeta.path.includes(null)) {
			return new TextEncoder().encode(JSON.stringify(claimValue));
		} else {
			if (claimValue.length > 1) {
				throw new Error(`Claim path without "select all in array" component returned more than 1 result: ${claimMeta.path}`);
			} else if (claimValue.length === 0) {
				return new Uint8Array([]);
			} else {
				return new TextEncoder().encode(JSON.stringify(claimValue[0]));
			}
		}
	});
}

function extractClaimsFromPayloads(
	payloads: (BufferSource | null)[],
	metadata: ClaimsMetadata,
): JptClaims {
	return metadata.claims.reduce(
		(claims: JptClaims, meta, i) => {
			const payload = payloads[i];
			if (payload === null) {
				return claims; // Undisclosed claim
			} else if (payload.byteLength === 0) {
				return claims; // Claim not issued
			} else {
				const value = JSON.parse(new TextDecoder().decode(payload));
				if (meta.path.length === 1 && typeof meta.path[0] === 'string') {
					const key = meta.path[0];
					if (key in claims) {
						throw new Error("Duplicate simple claim key: " + key);
					} else {
						claims.simple[key] = value;
						return claims;
					}
				} else {
					claims.complex.push({ path: meta.path, value });
					return claims;
				}
			}
		},
		{
			simple: {},
			complex: [],
		},
	);
}

export function findComplexClaim(jpt: IssuedJpt | PresentedJpt, path: ClaimPath): JptComplexClaim | undefined {
	return jpt.claims.complex.find(claim => pathEquals(claim.path, path));
}

export function parseJpt(jpt: string | IssuedJwp | PresentedJwp): IssuedJpt | PresentedJpt {
	const parsedJpt = parseJwp(jpt);
	const { issuerHeader, payloads, proof } = parsedJpt;
	const vctm = issuerHeader.vctm;
	if (!vctm) {
		throw new Error("No metadata in JPT issuer header: " + jpt);
	}

	const metadata: ClaimsMetadata = JSON.parse(new TextDecoder().decode(fromBase64Url(vctm[0])));
	if (!metadata?.claims) {
		throw new Error("Unrecognized metadata in JPT issuer header: " + jpt);
	}

	const claims = extractClaimsFromPayloads(payloads, metadata);
	if ("presentationHeader" in parsedJpt) {
		return {
			issuerHeader,
			presentationHeader: parsedJpt.presentationHeader,
			claims,
			proof,
		};

	} else {
		return {
			issuerHeader,
			claims,
			proof,
		};
	}
}
