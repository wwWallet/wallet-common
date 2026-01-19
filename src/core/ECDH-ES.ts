import { exportJWK, generateKeyPair } from "jose";
import { generateRandomIdentifier } from "./generateRandomIdentifier";

export async function generateECDHKeypair() {
	const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', { extractable: true });
	const [privateKeyJwk, publicKeyJwk] = await Promise.all([
		exportJWK(privateKey),
		exportJWK(publicKey),
	]);
	const kid = generateRandomIdentifier(20);
	return { privateKeyJwk: { kid, ...privateKeyJwk }, publicKeyJwk: { kid, ...publicKeyJwk } };
}
