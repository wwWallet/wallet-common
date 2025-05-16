import fs from "fs";

const mimeToExt: Record<string, string> = {
	"image/png": ".png",
	"image/jpeg": ".jpg",
	"image/gif": ".gif",
	"image/svg+xml": ".svg",
	"image/webp": ".webp",
	"image/bmp": ".bmp",
	"image/x-icon": ".ico",
	"image/tiff": ".tiff",
	"image/heif": ".heif"
};

export function convertDataUriToImage(dataUri: string, outputFileName = "output-image") {
	const matches = dataUri.match(/^data:([a-zA-Z+\/]+);(?:charset=utf-8;)?(base64,|utf8,|utf-8,)?(.+)$/);

	if (!matches) {
		throw new Error("Invalid Data URI");
	}

	const mimeType = matches[1];
	const encoding = matches[2];
	const data = matches[3];

	const fileExtension = mimeToExt[mimeType] || ".bin";

	let buffer: Buffer;
	if (encoding === "base64") {
		buffer = Buffer.from(data, "base64");
	} else {
		buffer = Buffer.from(decodeURIComponent(data), "utf-8");
	}

	const outputPath = `${outputFileName}${fileExtension}`;
	fs.writeFileSync(outputPath, buffer);
}
