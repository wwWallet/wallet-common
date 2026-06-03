import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { HashAlgorithm } from "../types";


const encoder = new TextEncoder();

const hasherAndAlgorithm: HasherAndAlg = {
	hasher: async (data: string | ArrayBuffer, alg: string) => {
		const encoded =
			typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);

		const v = await crypto.subtle.digest(alg, encoded);
		return new Uint8Array(v);
	},
	alg: HashAlgorithm.sha_256,
};

export async function parseRawSdJwt(credential: string) {
	return await SDJwt.fromEncode(credential, hasherAndAlgorithm.hasher);
}
