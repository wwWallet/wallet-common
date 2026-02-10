
export async function generateHS512Key() {
	const secret = await crypto.subtle.generateKey(
		{
			name: "HMAC",
			hash: "SHA-512",
			length: 512
		},
		true,
		["sign", "verify"]
	);
	const exportedKey = await crypto.subtle.exportKey("raw", secret as CryptoKey);
	const base64Key = Buffer.from(exportedKey).toString("base64");
	return { secret, exportedKey: "$b64:" + base64Key };
}

export async function importHS512Key(key: string): Promise<CryptoKey> {
	if (!key.startsWith("$b64:")) {
		throw new Error("Could not import HS512 key");
	}
	const raw = Buffer.from(key.split("$b64:")[1], "base64");
	const secret = await crypto.subtle.importKey(
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
