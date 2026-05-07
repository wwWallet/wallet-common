/**
 * Compression options for jose v4 using native Browser/Node CompressionStream API.
 * This satisfies the 'deflateRaw' and 'inflateRaw' requirements for zip: "DEF".
 */
export const compressionOptions = {
	deflateRaw: async (data: Uint8Array): Promise<Uint8Array> => {
		const stream = new Blob([data as BlobPart])
			.stream()
			.pipeThrough(new CompressionStream('deflate-raw'));
		return new Uint8Array(await new Response(stream).arrayBuffer());
	},
	inflateRaw: async (data: Uint8Array): Promise<Uint8Array> => {
		const stream = new Blob([data as BlobPart])
			.stream()
			.pipeThrough(new DecompressionStream('deflate-raw'));
		return new Uint8Array(await new Response(stream).arrayBuffer());
	}
};
