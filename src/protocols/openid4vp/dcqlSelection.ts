export type DcqlCredentialSelectionQuery = {
	credentials: Array<{ id: string }>;
	credential_sets?: Array<{ options: string[][]; required?: boolean }>;
};

const MAX_SELECTION_STATES = 4096;
const MAX_CREDENTIAL_SETS = 64;

export const validateDcqlCredentialSelection = (
	dcqlQuery: DcqlCredentialSelectionQuery,
	selectedCredentialIds: Iterable<string>
): string | null => {
	const selectedIds = new Set(selectedCredentialIds);
	const credentialIds = new Set(dcqlQuery.credentials.map((credential) => credential.id));
	for (const id of selectedIds) {
		if (!credentialIds.has(id)) return `Selection contains unknown DCQL credential id '${id}'`;
	}

	if (!dcqlQuery.credential_sets) {
		const missing = dcqlQuery.credentials.find((credential) => !selectedIds.has(credential.id));
		return missing ? `Selection does not contain required DCQL credential '${missing.id}'` : null;
	}

	const choices = dcqlQuery.credential_sets.map((credentialSet) => {
		const matchingOptions = credentialSet.options
			.filter((option) => option.every((id) => selectedIds.has(id)));
		return (credentialSet.required ?? true)
			? matchingOptions
			: [...matchingOptions, []];
	});
	if (choices.some((options) => options.length === 0)) {
		return "Selection does not satisfy a required DCQL credential set";
	}
	if (choices.length > MAX_CREDENTIAL_SETS) {
		return "DCQL credential-set selection is too complex";
	}

	const stateKey = (ids: Iterable<string>) => JSON.stringify(Array.from(ids).sort());
	const selectedState = stateKey(selectedIds);
	const visitedStates = new Set<string>();
	let complexityExceeded = false;
	const canExplainSelection = (setIndex: number, coveredIds: Set<string>): boolean => {
		const visitKey = `${setIndex}:${stateKey(coveredIds)}`;
		if (visitedStates.has(visitKey)) return false;
		visitedStates.add(visitKey);
		if (visitedStates.size > MAX_SELECTION_STATES) {
			complexityExceeded = true;
			return false;
		}
		if (setIndex === choices.length) return stateKey(coveredIds) === selectedState;

		for (const option of choices[setIndex]) {
			const nextCoveredIds = new Set(coveredIds);
			option.forEach((id) => nextCoveredIds.add(id));
			if (canExplainSelection(setIndex + 1, nextCoveredIds)) {
				return true;
			}
		}
		return false;
	};

	if (canExplainSelection(0, new Set())) return null;
	return complexityExceeded
		? "DCQL credential-set selection is too complex"
		: "Selection combines alternative, partial, or extraneous DCQL credential sets";
};
