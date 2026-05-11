import { cborEncode } from "@owf/mdoc";
import { calculateJwkThumbprint, type JWK } from "jose";
import { DigestHashAlgorithm } from "../../types";
import { base64urlToBytes } from "../../utils";

export type OpenId4VpHandoverType = "redirect" | "dc_api";

export async function buildOpenId4VpSessionTranscriptBytes(args: {
	subtle: SubtleCrypto;
	handoverType?: OpenId4VpHandoverType;
	clientId?: string;
	responseUri?: string;
	nonce: string;
	dcApiOrigin?: string;
	verifierEncryptionJwk?: JWK | JsonWebKey | Record<string, unknown>;
}): Promise<Uint8Array> {
	const handoverType = args.handoverType ?? "redirect";
	const thumbprintB64u = args.verifierEncryptionJwk
		? await calculateJwkThumbprint(args.verifierEncryptionJwk as JWK, "sha256")
		: null;
	const jwkThumbprint = thumbprintB64u ? base64urlToBytes(thumbprintB64u) : null;

	let handoverInfoBytes: Uint8Array;
	let handoverIdentifier: "OpenID4VPHandover" | "OpenID4VPDCAPIHandover";
	if (handoverType === "dc_api") {
		if (!args.dcApiOrigin) {
			throw new Error("Missing dcApiOrigin for OpenID4VP dc_api handover");
		}
		handoverInfoBytes = cborEncode([args.dcApiOrigin, args.nonce, jwkThumbprint]);
		handoverIdentifier = "OpenID4VPDCAPIHandover";
	} else {
		if (!args.clientId || !args.responseUri) {
			throw new Error("Missing clientId/responseUri for OpenID4VP redirect handover");
		}
		handoverInfoBytes = cborEncode([args.clientId, args.nonce, jwkThumbprint, args.responseUri]);
		handoverIdentifier = "OpenID4VPHandover";
	}

	const handoverInfoHash = new Uint8Array(
		await args.subtle.digest(DigestHashAlgorithm.SHA_256, handoverInfoBytes)
	);
	return cborEncode([null, null, [handoverIdentifier, handoverInfoHash]]);
}
