import { OpenIdClaim, SdJwtVcClaim } from "../schemas";

export function convertOpenid4vciToSdjwtvcClaims(
	metadataClaims?: OpenIdClaim[] | null,
): SdJwtVcClaim[] {
	const claims = metadataClaims ?? [];

	return claims.map(claim => {

		const display = (claim.display || []).map(d => ({
			lang: d.locale,
			label: d.name

		}));

		return {
			path: claim.path,
			...(display.length > 0 ? { display } : {})
		};
	});
}
