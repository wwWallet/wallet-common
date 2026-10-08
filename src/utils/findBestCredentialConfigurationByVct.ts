import type { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

function hasClaimPath(payload: unknown, path: Array<string | number | null>, pathIndex = 0): boolean {
	if (pathIndex >= path.length) return true;
	if (payload === null || payload === undefined) return false;

	const segment = path[pathIndex];
	if (segment === null) {
		return Array.isArray(payload)
			? payload.some((item) => hasClaimPath(item, path, pathIndex + 1))
			: false;
	}

	if (Array.isArray(payload)) {
		return typeof segment === "number" && segment in payload
			? hasClaimPath(payload[segment], path, pathIndex + 1)
			: false;
	}

	if (typeof payload !== "object") return false;

	const payloadRecord = payload as Record<string, unknown>;
	const key = String(segment);
	if (!Object.prototype.hasOwnProperty.call(payloadRecord, key)) return false;

	return hasClaimPath(payloadRecord[key], path, pathIndex + 1);
}

function scoreCredentialConfigurationMatch(
	configuration: CredentialConfigurationSupported,
	payload: Record<string, unknown>,
	payloadKeys: Set<string>
): number {
	return (configuration.credential_metadata?.claims ?? []).reduce((score, claim) => {
		if (hasClaimPath(payload, claim.path)) return score + 2;

		const topLevelKey = claim.path[0];
		if (typeof topLevelKey === "string" && payloadKeys.has(topLevelKey)) return score + 1;

		return score;
	}, 0);
}

export function findBestCredentialConfigurationByVct(
	credentialConfigurationsSupported: Record<string, CredentialConfigurationSupported>,
	vct: string,
	payload: Record<string, unknown>
): CredentialConfigurationSupported | undefined {
	const payloadKeys = new Set(Object.keys(payload));
	const matches = Object.values(credentialConfigurationsSupported).filter((configuration) =>
		'vct' in configuration && configuration.vct === vct
	);

	let bestMatch: CredentialConfigurationSupported | undefined;
	let bestScore = -1;

	for (const configuration of matches) {
		const score = scoreCredentialConfigurationMatch(configuration, payload, payloadKeys);

		// Keep the first match when scores tie, preserving issuer metadata order.
		if (!bestMatch || score > bestScore) {
			bestMatch = configuration;
			bestScore = score;
		}
	}

	return bestMatch;
}
