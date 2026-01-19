import { generateSecret } from "jose";
import * as webcrypto from "uncrypto";

export async function generateHS512Key() {
	const secret = await generateSecret("HS512", { extractable: true });
	const exportedKey = await webcrypto.subtle.exportKey("raw", secret as CryptoKey);
	const base64Key = Buffer.from(exportedKey).toString("base64");
	return { secret, exportedKey: "$b64:" + base64Key };
}

export async function importHS512Key(key: string): Promise<CryptoKey> {
	if (!key.startsWith("$b64:")) {
		throw new Error("Could not import HS512 key");
	}
	const raw = Buffer.from(key.split("$b64:")[1], "base64");
	const secret = await webcrypto.subtle.importKey(
		"raw",
		raw,
		{
			name: 'HMAC',
			hash: { name: 'SHA-512' },
		},
		false,
		['sign', 'verify']
	);
	return secret;
}
