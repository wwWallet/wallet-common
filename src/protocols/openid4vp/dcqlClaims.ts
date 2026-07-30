import type { DcqlClaimPath } from "./types";

const expandClaimPath = (
	value: unknown,
	path: DcqlClaimPath,
	offset: number,
	concretePath: Array<string | number>
): Array<Array<string | number>> => {
	if (offset === path.length) return [concretePath];
	const segment = path[offset];

	if (segment === null) {
		if (!Array.isArray(value) || value.length === 0) {
			throw new Error("DCQL null path selector requires a non-empty array");
		}
		return value.flatMap((item, index) =>
			expandClaimPath(item, path, offset + 1, [...concretePath, index])
		);
	}
	if (typeof segment === "number") {
		if (!Array.isArray(value) || segment < 0 || segment >= value.length) {
			throw new Error(`DCQL array index '${segment}' does not exist`);
		}
		return expandClaimPath(value[segment], path, offset + 1, [...concretePath, segment]);
	}
	if (value === null || typeof value !== "object" || !(segment in value)) {
		throw new Error(`DCQL object key '${segment}' does not exist`);
	}
	return expandClaimPath(
		(value as Record<string, unknown>)[segment],
		path,
		offset + 1,
		[...concretePath, segment]
	);
};

export const generatePresentationFrameForDCQLPaths = (
	paths: DcqlClaimPath[],
	claims: Record<string, unknown>
): Record<string, any> => {
	const frame: Record<string, any> = {};
	const concretePaths = paths.flatMap((path) => expandClaimPath(claims, path, 0, []));

	for (const path of concretePaths) {
		let current = frame;
		path.forEach((segment, index) => {
			const key = String(segment);
			if (index === path.length - 1) {
				current[key] = true;
				return;
			}
			const child = current[key];
			if (child === true) return;
			if (!child || typeof child !== "object") current[key] = {};
			current = current[key] as Record<string, any>;
		});
	}
	return frame;
};
