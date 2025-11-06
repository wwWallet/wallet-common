import { OpenIdClaim } from "../schemas";
import { ClaimMetadataEntry, ClaimDisplayEntry } from "../schemas/SdJwtVcTypeMetadataSchema";

export function convertOpenid4vciToSdjwtvcClaims(
	metadataClaims?: OpenIdClaim[] | null,
): ClaimMetadataEntry[] {
	if (!metadataClaims?.length) return [];

	return metadataClaims
		.map<ClaimMetadataEntry | null>((claim) => {

			// Build ClaimDisplayEntry[]
			const normalizedDisplay: ClaimDisplayEntry[] = (claim.display ?? [])
				.filter(
					(d): d is { locale: string; name: string } =>
						typeof d?.locale === "string" &&
						d.locale.trim().length > 0 &&
						typeof d?.name === "string" &&
						d.name.trim().length > 0
				)
				.map(d => ({
					locale: d.locale.trim(),
					label: d.name.trim(),
				}));

			return {
				path: claim.path,
				...(normalizedDisplay.length > 0 ? { display: normalizedDisplay } : {}),
			};
		})
		.filter((e): e is ClaimMetadataEntry => e !== null);
}
