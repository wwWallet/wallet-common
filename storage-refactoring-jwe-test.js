import * as jose from 'jose';
import * as arkg from './dist/arkg/index.js';
import * as ec from './dist/arkg/ec.js';
import { fromBase64Url, toBase64Url } from "./dist/utils/util.js";


const arkgInstance = arkg.getEcInstance('ARKG-P256');
const arkgCtx = new TextEncoder().encode('test');
const encryptionArkgSeedIkm = {
	ikm_bl: new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("ikm_bl"))),
	ikm_kem: new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("ikm_kem"))),
};
const [seedPub, ] = await arkgInstance.deriveSeed(encryptionArkgSeedIkm.ikm_bl, encryptionArkgSeedIkm.ikm_kem);
const ikm = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("ikm")));
const [pub, kh] = await arkgInstance.derivePublicKey(seedPub, ikm, arkgCtx);
const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", await ec.publicKeyFromPoint("ECDH", "P-256", pub));
const encPub = {
	kty,
	kid: toBase64Url(kh),
	alg: 'ECDH-ES+A256KW',
	crv, x, y,
};
console.log({ encryptionArkgSeedIkm: { ikm_bl: toBase64Url(encryptionArkgSeedIkm.ikm_bl), ikm_kem: toBase64Url(encryptionArkgSeedIkm.ikm_kem) } });
console.log({ encPub });


const enc = await new jose.CompactEncrypt(
	new TextEncoder().encode(JSON.stringify({ foo: "bar" }))
).setProtectedHeader({
	enc: 'A256GCM',
	alg: 'ECDH-ES+A256KW',
	kid: encPub.kid,
	aud: await jose.calculateJwkThumbprint(encPub, "sha256"),
}).encrypt(await crypto.subtle.importKey("jwk", encPub, { name: "ECDH", namedCurve: encPub.crv }, true, []));
console.log({ enc });
const header = jose.decodeProtectedHeader(enc);

const decrypted = await (async () => {
	const [, seedPri] = await arkgInstance.deriveSeed(encryptionArkgSeedIkm.ikm_bl, encryptionArkgSeedIkm.ikm_kem);
	const privateKeyRaw = await arkgInstance.derivePrivateKey(seedPri, fromBase64Url(header.kid), arkgCtx);
	const privateKey = await ec.privateKeyFromScalar("ECDH", "P-256", privateKeyRaw, false, ["deriveBits"]);
	return await jose.compactDecrypt(enc, privateKey, {
		contentEncryptionAlgorithms: ['A256GCM'],
		keyManagementAlgorithms: ['ECDH-ES+A256KW'],
	});
})();
console.log({ decrypted });
