import { X509Certificate } from "@peculiar/x509";
import { Buffer } from "buffer";
import { verifyCertificate } from "./verifyCertificate";

function certificateBytes(certificate: string): Buffer {
	return Buffer.from(certificate.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, ""), "base64");
}

export async function verifyX5C(x5c: string[], trustedCertificates: string[]): Promise<boolean> {
	if (x5c.length === 0) {
		return true;
	}
	if (trustedCertificates.length === 0) {
		return false;
	}
	try {
		const trustedIndex = x5c.findIndex(certificate => trustedCertificates.some(
			trusted => certificateBytes(trusted).equals(certificateBytes(certificate)),
		));
		if (trustedIndex !== -1) {
			// Validate up to the exact trust match, ignoring its trailing issuers.
			const trustedCertificate = x5c[trustedIndex];
			const certificate = new X509Certificate(Uint8Array.from(certificateBytes(trustedCertificate)));
			const now = new Date();
			if (now < certificate.notBefore || now > certificate.notAfter) {
				return false;
			}
			return await verifyX5C(x5c.slice(0, trustedIndex), [trustedCertificate]);
		}

		// No exact match: establish trust through the last certificate's issuer.
		const lastCertificate: string = x5c[x5c.length - 1];
		const lastCertificatePem = `-----BEGIN CERTIFICATE-----\n${lastCertificate}\n-----END CERTIFICATE-----`;
		if (!await verifyCertificate(lastCertificatePem, trustedCertificates)) {
			return false;
		}

		return x5c.length === 1 || await verifyX5C(x5c.slice(0, -1), [lastCertificate]);
	} catch {
		return false;
	}
}
