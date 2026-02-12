import type { FriendlyNameCallback } from "../types";
import { matchDisplayByLocale } from "../utils/matchLocalizedDisplay";
import type { TypeDisplayEntry } from "../schemas/SdJwtVcTypeMetadataSchema";
import type { CredentialConfigurationSupported } from "../schemas/CredentialConfigurationSupportedSchema";

type IssuerDisplayEntry =
	NonNullable<
		NonNullable<CredentialConfigurationSupported["credential_metadata"]>["display"]
	>[number];

type FriendlyNameResolverOptions = {
	credentialDisplayArray?: TypeDisplayEntry[];
	issuerDisplayArray?: IssuerDisplayEntry[];
	fallbackName?: string;
};

export function friendlyNameResolver({
	credentialDisplayArray,
	issuerDisplayArray,
	fallbackName = "Verifiable Credential",
}: FriendlyNameResolverOptions): FriendlyNameCallback {
	return async (preferredLangs: string[] = ["en-US"]): Promise<string | null> => {
		// 1) Credential display name
		const credentialDisplayLocalized = matchDisplayByLocale(
			credentialDisplayArray,
			preferredLangs
		);

		if (credentialDisplayLocalized?.name) {
			return credentialDisplayLocalized.name;
		}

		// 2) Issuer display name
		const issuerDisplayLocalized = matchDisplayByLocale(
			issuerDisplayArray,
			preferredLangs
		);

		if (issuerDisplayLocalized?.name) {
			return issuerDisplayLocalized.name;
		}

		return fallbackName;
	};
}
