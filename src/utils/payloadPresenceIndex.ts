function isIgnoredKey(key: string, prefixes: string[]) {
	return prefixes.some((p) => key.startsWith(p));
}

export function buildPresenceIndex(
	root: unknown,
	ignoreKeyPrefixes: string[] = ["_sd"]
): Set<string> {
	const paths = new Set<string>();

	function visit(node: unknown, acc: (string | number)[]) {
		if (acc.length) {
			// ✅ Don't add path if node is an empty object
			if (isEmptyObject(node, ignoreKeyPrefixes)) return;
			paths.add(stringify(acc));
		}

		if (Array.isArray(node)) {
			for (let i = 0; i < node.length; i++) visit(node[i], [...acc, i]);
			return;
		}

		if (node && typeof node === "object") {
			for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
				if (isIgnoredKey(k, ignoreKeyPrefixes)) continue;
				visit(v, [...acc, k]);
			}
		}
	}

	visit(root, []);
	return paths;
}

function isEmptyObject(
	node: unknown,
	ignoreKeyPrefixes: string[]
): boolean {
	if (!node || typeof node !== "object" || Array.isArray(node)) return false;
	const keys = Object.keys(node);
	const filteredKeys = keys.filter((k) => !isIgnoredKey(k, ignoreKeyPrefixes));
	return filteredKeys.length === 0; // empty or only ignored keys
}

function stringify(segs: (string | number)[]): string {
	return segs
		.map((s) =>
			typeof s === "number"
				? `[${s}]`
				: s.includes(".")
					? `["${s}"]`
					: `.${s}`
		)
		.join("")
		.replace(/^\./, "");
}

export function pathIsPresent(
	index: Set<string>,
	claimPath: Array<string | number | null>
): boolean {
	const pattern = claimPath
		.map((seg) => {
			if (seg === null) return `(\\.[^\\.\\[]+|\\[[0-9]+\\])*`; // wildcard
			if (typeof seg === "number") return `\\[${seg}\\]`;
			return seg.includes(".")
				? `\\["${escapeRegex(seg)}"\\]`
				: `\\.${escapeRegex(seg)}`;
		})
		.join("");

	const rx = new RegExp(`^${pattern}$`);
	for (const p of index) {
		const dotted = p.startsWith(".") || p.startsWith("[") ? p : "." + p;
		if (rx.test(dotted)) return true;
	}
	return false;

	function escapeRegex(s: string) {
		return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	}
}
