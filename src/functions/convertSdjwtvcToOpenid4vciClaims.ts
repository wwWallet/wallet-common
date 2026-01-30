import {
	ClaimMetadataEntry,
	ClaimDisplayEntry,
} from "../schemas/SdJwtVcTypeMetadataSchema";
import { OpenIdClaim } from "../schemas";

/**
 * Converts SD-JWT VC type-metadata claims to OpenID4VCI claims.
 * - display[].label -> display[].name
 * - preserves mandatory if present
 * - removes undefined fields
 */
export function convertSdjwtvcToOpenid4vciClaims(
	claims?: ClaimMetadataEntry[] | null,
): OpenIdClaim[] {
	if (!claims?.length) return [];

	return claims.map<OpenIdClaim>((claim) => {
		// Map display entries
		const display = (claim.display ?? [])
			.filter(
				(d): d is ClaimDisplayEntry =>
					typeof d?.locale === "string" &&
					d.locale.trim() !== "" &&
					typeof d?.label === "string" &&
					d.label.trim() !== ""
			)
			.map((d) => ({
				locale: d.locale.trim(),
				name: d.label.trim(),
			}));

		// Only include mandatory if explicitly present (true OR false)
		const hasMandatory = Object.prototype.hasOwnProperty.call(
			claim,
			"mandatory",
		);

		const result: any = {
			path: claim.path,
			...(display.length > 0 ? { display } : {}),
			...(hasMandatory ? { mandatory: claim.mandatory } : {}),
		};

		return result as OpenIdClaim;
	});
}

export default convertSdjwtvcToOpenid4vciClaims;
