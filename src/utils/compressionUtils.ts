/**
 * Raw DEFLATE compression utilities for JOSE workflows.
 */
export const compressionUtils = {
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
