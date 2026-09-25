import { exportJWK, generateKeyPair } from "jose";
import { generateRandomIdentifier } from "../utils";

export async function generateECDHKeypair() {
	const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', { extractable: true });
	const [privateKeyJwk, publicKeyJwk] = await Promise.all([
		exportJWK(privateKey),
		exportJWK(publicKey),
	]);
	const kid = generateRandomIdentifier(20);
	return {
		privateKeyJwk: {
			...privateKeyJwk,
			kid,
			alg: 'ECDH-ES',
			use: 'enc'
		},
		publicKeyJwk: {
			...publicKeyJwk,
			kid,
			alg: 'ECDH-ES',
			use: 'enc'
		}
	};
}
