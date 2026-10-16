import { fromBase64, toBase64 } from "./util";

const IMAGE_MIME_TYPES = {
	jpeg: "image/jpeg",
	jp2: "image/jp2",
	png: "image/png",
	gif: "image/gif",
	webp: "image/webp",
} as const;

const SUPPORTED_IMAGE_DATA_URI = /^data:image\/(?:jpeg|jp2|png|gif|webp);base64,[a-z0-9+/]+={0,2}$/i;
const SVG_IMAGE_DATA_URI = /^data:image\/svg\+xml;base64,([a-z0-9+/]+={0,2})$/i;
const UNSAFE_SVG_CONTENT = /<script\b|<foreignObject\b|\bon[a-z]+\s*=|\b(?:href|src)\s*=\s*["'](?:https?:|\/\/)|\burl\s*\(/i;

function isSafeSvgImageDataUri(value: string): boolean {
	const match = SVG_IMAGE_DATA_URI.exec(value);
	if (!match) return false;

	try {
		const svg = new TextDecoder("utf-8", { fatal: true }).decode(fromBase64(match[1]));
		return /<svg(?:\s|>)/i.test(svg) && /<\/svg\s*>/i.test(svg) && !UNSAFE_SVG_CONTENT.test(svg);
	} catch {
		return false;
	}
}

function isSupportedImageDataUri(value: string): boolean {
	return SUPPORTED_IMAGE_DATA_URI.test(value) || isSafeSvgImageDataUri(value);
}

function serializedBytesToUint8Array(value: unknown): Uint8Array | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;

	const entries = Object.entries(value);
	if (
		entries.length === 0 ||
		!entries.every(([key, byte], index) => key === String(index) && Number.isInteger(byte) && Number(byte) >= 0 && Number(byte) <= 255)
	) return undefined;

	return Uint8Array.from(entries.map(([, byte]) => Number(byte)));
}

function imageValueToBytes(value: unknown): Uint8Array | undefined {
	if (value instanceof ArrayBuffer) {
		return new Uint8Array(value);
	}
	if (ArrayBuffer.isView(value)) {
		return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
	}
	return serializedBytesToUint8Array(value);
}

function imageBytesToBase64(bytes: Uint8Array): string {
	const buffer = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(buffer).set(bytes);
	return toBase64(buffer);
}

function detectImageMimeType(bytes: Uint8Array): string | undefined {
	if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return IMAGE_MIME_TYPES.jpeg;
	if (
		bytes.length >= 12 &&
		bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0x0c &&
		bytes[4] === 0x6a && bytes[5] === 0x50 && bytes[6] === 0x20 && bytes[7] === 0x20 &&
		bytes[8] === 0x0d && bytes[9] === 0x0a && bytes[10] === 0x87 && bytes[11] === 0x0a
	) return IMAGE_MIME_TYPES.jp2;
	if (bytes[0] === 0xff && bytes[1] === 0x4f && bytes[2] === 0xff && bytes[3] === 0x51) return IMAGE_MIME_TYPES.jp2;
	if (
		bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 &&
		bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a
	) return IMAGE_MIME_TYPES.png;
	if (["GIF87a", "GIF89a"].includes(String.fromCharCode(...bytes.subarray(0, 6)))) return IMAGE_MIME_TYPES.gif;
	if (
		String.fromCharCode(...bytes.subarray(0, 4)) === "RIFF" &&
		String.fromCharCode(...bytes.subarray(8, 12)) === "WEBP"
	) return IMAGE_MIME_TYPES.webp;
	return undefined;
}

function encodedImageToDataUri(value: unknown): string | undefined {
	const bytes = imageValueToBytes(value);
	if (!bytes?.length) return undefined;

	const mimeType = detectImageMimeType(bytes);
	if (!mimeType) return undefined;

	return `data:${mimeType};base64,${imageBytesToBase64(bytes)}`;
}

export function imageValueToDataUri(value: unknown): string | undefined {
	if (typeof value === "string") {
		return isSupportedImageDataUri(value) ? value : undefined;
	}

	return encodedImageToDataUri(value);
}
