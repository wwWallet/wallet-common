import { verifyCertificate } from "./verifyCertificate";

/**
 * Verify an X.509 certificate chain (x5c) against trusted root certificates.
 *
 * @param x5c - Array of base64-encoded certificates (leaf first, root last)
 * @param trustedCertificates - Array of trusted root certificates in PEM format
 * @returns Promise<boolean> - True if chain validates to a trusted root
 *
 * @deprecated Trust evaluation is now delegated to the AuthZEN backend at the
 * protocol level. This function is only used for backwards compatibility.
 * New code should set `delegateTrustToBackend: true` in the Context and rely on
 * protocol-level trust evaluation via AuthZEN before credentials are
 * issued/presented.
 */
export async function verifyX5C(x5c: string[], trustedCertificates: string[]): Promise<boolean> {
	if (x5c.length === 0) {
		return true;
	}
	const lastCertificate: string = x5c[x5c.length - 1];
	const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;
	const certificateValidationResult = await verifyCertificate(lastCertificatePem, trustedCertificates);
	const lastCertificateIsRootCa = trustedCertificates.map((c) => c.trim()).includes(lastCertificatePem);

	if (!certificateValidationResult && !lastCertificateIsRootCa) {
		return false;
	}

	return await verifyX5C(x5c.slice(0, -1), [lastCertificate]);
}
