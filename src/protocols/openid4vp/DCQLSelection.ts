import { DcqlQuery, DcqlPresentationResult } from 'dcql';

export type DcqlPath = (string | number | null)[];
export interface DcqlSelectedCredential {
	/** Logical credential (issuance batch), never an interchangeable copy. */
	batchId: number;
	/** Concrete interchangeable copy used for consent; never a separate logical choice. */
	credentialId?: number;
	instanceId?: number;
	claimSetIndex?: number;
	disclosurePaths: DcqlPath[];
	/** Actual disclosed claims, including mandatory and indivisible disclosures. */
	disclosedClaims: Record<string, unknown>;
}
export type DcqlSelection = Map<string, DcqlSelectedCredential[]>;
export interface DcqlRequirement {
	setIndex: number;
	required: boolean;
	options: { optionIndex: number; queryIds: string[]; available: boolean; reason?: string }[];
}
export interface DcqlCredentialMatch {
	credentials: number[];
	candidates: DcqlSelectedCredential[];
	multiple: boolean;
	requirements: DcqlRequirement[];
	inventoryCanSatisfy: boolean;
	failure?: string;
	/** Matching diagnostics; protocol values must not be rendered as arbitrary display text. */
	failures: {
		inputCredentialIndex: number;
		metadata: boolean;
		claims: boolean;
		trustedAuthorities: boolean;
	}[];
	requestedFields: { name: string; purpose: string; path?: DcqlPath }[];
}
export type DcqlMatches = Record<string, DcqlCredentialMatch>;

export function dcqlRequirements(
	query: DcqlQuery.Input,
	result: ReturnType<typeof DcqlQuery.query>,
): DcqlRequirement[] {
	const parsed = DcqlQuery.parse(query);
	return (
		parsed.credential_sets ?? parsed.credentials.map((c) => ({ required: true, options: [[c.id]] }))
	).map((set, setIndex) => ({
		setIndex,
		required: set.required,
		options: set.options.map((queryIds, optionIndex) => {
			const available = result.credential_sets
				? !!result.credential_sets[setIndex].matching_options?.some(
						(option) => JSON.stringify(option) === JSON.stringify(queryIds),
					)
				: queryIds.every((id) => result.credential_matches[id]?.success);
			const missing = queryIds.filter((id) => !result.credential_matches[id]?.success).length;
			return {
				optionIndex,
				queryIds,
				available,
				...(!available
					? { reason: `${missing} credential request(s) have no matching credentials.` }
					: {}),
			};
		}),
	}));
}

/** Reconcile the union of active options. Shared query selections survive option changes. */
export function reconcileDcqlSelection(
	matches: DcqlMatches,
	choices: (number | null)[],
	previous: DcqlSelection,
): DcqlSelection {
	const requirements = Object.values(matches)[0]?.requirements ?? [];
	const active = new Set(
		requirements.flatMap(
			(set, i) => set.options.find((o) => o.optionIndex === choices[i])?.queryIds ?? [],
		),
	);
	return new Map(
		[...active].map((id) => [id, previous.get(id) ?? matches[id].candidates.slice(0, 1)]),
	);
}
export function dcqlSelectionIsValid(
	matches: DcqlMatches,
	choices: (number | null)[],
	selection: DcqlSelection,
): boolean {
	const requirements = Object.values(matches)[0]?.requirements ?? [];
	if (
		!requirements.every((set, i) =>
			choices[i] === null
				? !set.required
				: set.options.some((o) => o.optionIndex === choices[i] && o.available),
		)
	)
		return false;
	const active = reconcileDcqlSelection(matches, choices, selection);
	return (
		active.size === selection.size &&
		[...selection].every(([id, instances]) => {
			const match = matches[id];
			return (
				active.has(id) &&
				!!match &&
				instances.length > 0 &&
				(match.multiple || instances.length === 1) &&
				new Set(instances.map((i) => i.batchId)).size === instances.length &&
				instances.every((instance) => match.candidates.some((c) => c.batchId === instance.batchId))
			);
		})
	);
}

export function validateDcqlPresentation(
	presentation: Record<string, unknown[]>,
	query: DcqlQuery.Input,
) {
	const parsed = DcqlQuery.parse(query);
	DcqlQuery.validate(parsed);
	for (const [id, entries] of Object.entries(presentation)) {
		const descriptor = parsed.credentials.find((c) => c.id === id);
		if (
			!descriptor ||
			!Array.isArray(entries) ||
			entries.length === 0 ||
			(!descriptor.multiple && entries.length !== 1)
		)
			throw new Error('Invalid DCQL presentation entries');
	}
	const result = DcqlPresentationResult.fromDcqlPresentation(presentation as any, {
		dcqlQuery: parsed,
	});
	DcqlPresentationResult.validate(result);
	return result;
}

/** Expand only array wildcards, preserving string object keys and numeric indexes. */
export function expandDcqlPaths(paths: DcqlPath[], claims: unknown): (string | number)[][] {
	const expand = (
		path: DcqlPath,
		value: any,
		prefix: (string | number)[],
	): (string | number)[][] => {
		if (!path.length) {
			// A requested object includes all of its descendants, even when they are separately disclosable.
			if (value && typeof value === 'object' && Object.keys(value).length)
				return Object.entries(value).flatMap(([key, child]) =>
					expand([], child, [...prefix, Array.isArray(value) ? Number(key) : key]),
				);
			return [prefix];
		}
		const [head, ...tail] = path;
		if (head === null)
			return Array.isArray(value) ? value.flatMap((v, i) => expand(tail, v, [...prefix, i])) : [];
		if (
			typeof head === 'number'
				? !Array.isArray(value)
				: !value || typeof value !== 'object' || Array.isArray(value)
		)
			return [];
		return value[head] === undefined ? [] : expand(tail, value[head], [...prefix, head]);
	};
	return paths.flatMap((path) => expand(path, claims, []));
}
export function dcqlDisclosureFrame(paths: DcqlPath[], claims: unknown): Record<string, any> {
	const frame: Record<string, any> = Object.create(null);
	for (const path of expandDcqlPaths(paths, claims)) {
		let node = frame;
		for (let i = 0; i < path.length; i++) {
			const key = path[i];
			if (node[key] === true) break;
			if (i === path.length - 1) node[key] = true;
			else node = node[key] ??= Object.create(null);
		}
	}
	return frame;
}

/** Stable consent comparison, including CBOR maps and binary/date values. */
export function dcqlClaimsFingerprint(value: unknown): string {
	const normalize = (v: any): any => {
		if (v instanceof Map) return normalize(Object.fromEntries(v));
		if (v instanceof Uint8Array) return { bytes: Array.from(v) };
		if (v instanceof Date) return { date: v.toISOString() };
		if (Array.isArray(v)) return v.map(normalize);
		if (v && typeof v === 'object')
			return Object.fromEntries(
				Object.keys(v)
					.sort()
					.map((key) => [key, normalize(v[key])]),
			);
		return v;
	};
	return JSON.stringify(normalize(value));
}
