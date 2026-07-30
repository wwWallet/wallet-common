export type DcqlCredentialSelectionQuery = {
	credentials: Array<{ id: string }>;
	credential_sets?: Array<{ options: string[][]; required?: boolean }>;
};

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

	const satisfiedOptions = dcqlQuery.credential_sets.flatMap((credentialSet) =>
		credentialSet.options.filter((option) => option.every((id) => selectedIds.has(id)))
	);
	const unsatisfiedRequiredSet = dcqlQuery.credential_sets.find((credentialSet) =>
		(credentialSet.required ?? true)
		&& !credentialSet.options.some((option) => option.every((id) => selectedIds.has(id)))
	);
	if (unsatisfiedRequiredSet) return "Selection does not satisfy a required DCQL credential set";

	const idsInSatisfiedOptions = new Set(satisfiedOptions.flat());
	const partialOrExtraneous = Array.from(selectedIds).find((id) => !idsInSatisfiedOptions.has(id));
	return partialOrExtraneous
		? `Selection contains a partial or extraneous DCQL credential set at '${partialOrExtraneous}'`
		: null;
};
