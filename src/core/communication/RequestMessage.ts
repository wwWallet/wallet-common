export type RequestMessage = {
	url: string;

	data: unknown;
	headers: Record<string, string>;
	status: number;
}
