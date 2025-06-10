export function toU8(b: BufferSource): Uint8Array {
	if (b instanceof Uint8Array) {
		return b;
	} else if (b instanceof ArrayBuffer) {
		return new Uint8Array(b);
	} else {
		return new Uint8Array(b.buffer);
	}
}

export function toHex(b: BufferSource): string {
	return toU8(b).reduce((s, byte) => s + byte.toString(16).padStart(2, '0'), '');
}

export const HEX_ERR_LENGTH_ODD = 'LENGTH_ODD';
export const HEX_ERR_INVALID_DIGITS = 'INVALID_DIGITS';

export function fromHex(hex: string): BufferSource {
	/* eslint-disable no-bitwise */

	const normalized = hex.replaceAll(' ', '');

	if (normalized.length % 2 !== 0) {
		throw Error(`Invalid hex string: ${hex}`, { cause: HEX_ERR_LENGTH_ODD });

	} else if (!normalized.match(/^[a-fA-F0-9]*$/u)) {
		throw Error(`Invalid hex string: ${hex}`, { cause: HEX_ERR_INVALID_DIGITS });

	} else {
		return new Uint8Array(
			normalized
				.split('')
				.reduce(
					(bytes: number[], digit, i) => {
						if (i % 2 === 0) {
							bytes.push(parseInt(digit, 16) << 4);
						} else {
							bytes[bytes.length - 1] |= parseInt(digit, 16);
						}
						return bytes;
					},
					[],
				)
		);
	}
};

export function concat(...b: BufferSource[]): ArrayBuffer {
	return b.map(toU8).reduce((a, b) => new Uint8Array([...a, ...b]), new Uint8Array([])).buffer;
}

/**
	Convert a big-endian octet string to a nonnegative integer.

	@see https://www.rfc-editor.org/rfc/rfc8017.html#section-4.2
	*/
export function OS2IP(binary: BufferSource): bigint {
	return toU8(binary).reduce(
		(result: bigint, b: number) => (result << 8n) + BigInt(b),
		0n,
	);
}

/**
	Convert a nonnegative integer to a big-endian octet string of a specified length.

	@see https://www.rfc-editor.org/rfc/rfc8017.html#section-4.1
	*/
export function I2OSP(a: bigint, length: number): ArrayBuffer {
	return new Uint8Array(length).map(
		(_, i: number): number =>
			Number(BigInt.asUintN(8, a >> (BigInt(length - 1 - i) * 8n)))
	).buffer;
}

export function toBase64(binary: BufferSource): string {
	const uint8Array = toU8(binary);
	const chunkSize = 0x8000; // 32KB
	let result = '';
	for (let i = 0; i < uint8Array.length; i += chunkSize) {
		const chunk = uint8Array.subarray(i, i + chunkSize);
		result += String.fromCharCode(...chunk);
	}
	return btoa(result);
}

export function toBase64Url(binary: BufferSource): string {
	return toBase64(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function byteArrayEquals(a: BufferSource, b: BufferSource): boolean {
	return toBase64(a) === toBase64(b);
}

function base64pad(s: string): string {
	const m = s.length % 4;
	if (m === 0) {
		return s;
	} else if (m === 2) {
		return s + "==";
	} else if (m === 3) {
		return s + "=";
	} else {
		throw Error("Invalid length of Base64 encoded data");
	}
}

export function fromBase64(s: string): Uint8Array {
	return new Uint8Array(Array.from(atob(base64pad(s))).map(c => c.charCodeAt(0)));
}

export function fromBase64Url(s: string): Uint8Array {
	return fromBase64(s.replace(/-/g, "+").replace(/_/g, "/"));
}
