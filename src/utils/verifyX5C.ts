import { verifyCertificate } from "./verifyCertificate";

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
