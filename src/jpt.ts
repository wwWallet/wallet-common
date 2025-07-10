export type ClaimPath = (string | null | number)[];
export type ClaimsMetadata = { claims: { path: ClaimPath }[] };

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

export function extractClaimFromPayloads(
	payloads: (BufferSource | null)[],
	path: ClaimPath,
	metadata: ClaimsMetadata,
): { value: any } | "undisclosed" | "not-found" {
	function pathEquals(a: ClaimPath, b: ClaimPath): boolean {
		return (a === b) || ((a && b) && (a.length === b.length) && a.every((va, i) => va === b[i]));
	}

	const payloadIndex = metadata.claims.findIndex(meta => pathEquals(meta.path, path));
	if (payloadIndex >= 0) {
		if (payloadIndex < payloads.length) {
			const payload = payloads[payloadIndex];
			if (payload === null) {
				return "undisclosed";
			} else if (payload.byteLength === 0) {
				return "not-found";
			} else {
				return { value: JSON.parse(new TextDecoder().decode(payload)) };
			}
		} else {
			return "not-found";
		}
	} else {
		throw new Error("Claim not found in metadata: " + path);
	}
}
