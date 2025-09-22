type ClaimPathSeg = string | number | null;

export function ClaimsWithRequired<T extends { path: ClaimPathSeg[] }>(
	claims: ReadonlyArray<T> | undefined,
	isPresent: (path: ClaimPathSeg[]) => boolean
): Array<T & { required: boolean }> | undefined {
	if (!claims?.length) return claims as unknown as any;
	return claims.map((c) => ({ ...c, required: isPresent(c.path) }));
}
