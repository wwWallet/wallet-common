import { BasicConstraintsExtension, X509CertificateGenerator } from "@peculiar/x509";
import { afterEach, assert, beforeEach, describe, it, vi } from "vitest";
import { verifyX5C } from "./verifyX5C";

// this x5c is signed by the first element in the trustedCertificates array
const x5c = [
	"MIICyzCCAnGgAwIBAgIULnrxux9sI34oqbby3M4lSKOs8owwCgYIKoZIzj0EAwIwPzELMAkGA1UEBhMCRVUxFTATBgNVBAoMDHd3V2FsbGV0Lm9yZzEZMBcGA1UEAwwQd3dXYWxsZXQgUm9vdCBDQTAeFw0yNTA0MjkxMDI5NTNaFw0yNjA0MjkxMDI5NTNaMEExCzAJBgNVBAYTAkVVMRUwEwYDVQQKDAx3d1dhbGxldC5vcmcxGzAZBgNVBAMMEmxvY2FsLnd3d2FsbGV0Lm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFVivGt53M4qEP06QT20BSlGiMIdzLLvG+b9fq/fHKM+NGT+a3snXiPwU7X7jrOFWxwyjZeean40+vx6Gy06VfqjggFHMIIBQzAdBgNVHQ4EFgQUM/A3FTQLjww5/9u01MX/SRyVqaUwHwYDVR0jBBgwFoAU0HGu3T+/Wqh3yNifz9sNd+HPBS4wDgYDVR0PAQH/BAQDAgeAMDIGA1UdEgQrMCmBEWluZm9Ad3d3YWxsZXQub3JnhhRodHRwczovL3d3d2FsbGV0Lm9yZzASBgNVHSUECzAJBgcogYxdBQECMAwGA1UdEwEB/wQCMAAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cHM6Ly93d3dhbGxldC5vcmcvaWFjYS9jcmwvd3d3YWxsZXRfb3JnX2lhY2EuY3JsMFUGA1UdEQROMEyCEmxvY2FsLnd3d2FsbGV0Lm9yZ4IZbG9jYWwtaXNzdWVyLnd3d2FsbGV0Lm9yZ4IbbG9jYWwtdmVyaWZpZXIud3d3YWxsZXQub3JnMAoGCCqGSM49BAMCA0gAMEUCIQCQ8h+5krhO+f4woReDY1D7CaM6qCda3m814e6DLvOphAIgHQL+Wm7WFRwxgjzMLN37RojJGrZbF4OFChIkmm0uu5o="
];

const trustedCertificates = [
	`-----BEGIN CERTIFICATE-----
MIICQDCCAeegAwIBAgIUa5v+g+yHrVdDFEfRy8GyoGtcT4YwCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCRVUxFTATBgNVBAoMDHd3V2FsbGV0Lm9yZzEZMBcGA1UEAwwQ
d3dXYWxsZXQgUm9vdCBDQTAeFw0yNTA0MjIxMDM5NDZaFw00MDA0MTgxMDM5NDZa
MD8xCzAJBgNVBAYTAkVVMRUwEwYDVQQKDAx3d1dhbGxldC5vcmcxGTAXBgNVBAMM
EHd3V2FsbGV0IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASkZIoc
6df1R0mEWz3qHQxgRjKDtVTZvDzhPCEqVTePw4zSzy8T0VCdOH77ItRP1w3Rwjeg
vHrY1CzmMNtQDWoMo4HAMIG9MB0GA1UdDgQWBBTQca7dP79aqHfI2J/P2w134c8F
LjAOBgNVHQ8BAf8EBAMCAQYwMgYDVR0SBCswKYERaW5mb0B3d3dhbGxldC5vcmeG
FGh0dHBzOi8vd3d3YWxsZXQub3JnMBIGA1UdEwEB/wQIMAYBAf8CAQAwRAYDVR0f
BD0wOzA5oDegNYYzaHR0cHM6Ly93d3dhbGxldC5vcmcvaWFjYS9jcmwvd3d3YWxs
ZXRfb3JnX2lhY2EuY3JsMAoGCCqGSM49BAMCA0cAMEQCIF+qqe7urRAop2jQJ6B9
fYvvp4c4HYxsWLNa9aYpCWxxAiAGgtVdZWW19dDU1G0AGy8FTWlcKiczWyVIQtvA
L3rT4w==
-----END CERTIFICATE-----
`,
	`-----BEGIN CERTIFICATE-----
MIICMzCCAdqgAwIBAgIUdgESbTG9nxSXVImFdFHHAHGJ9RwwCgYIKoZIzj0EAwIw
IDERMA8GA1UEAwwId3dXYWxsZXQxCzAJBgNVBAYTAkdSMB4XDTI1MDMwNjE1Mzcz
M1oXDTM1MDMwNDE1MzczM1owIDERMA8GA1UEAwwId3dXYWxsZXQxCzAJBgNVBAYT
AkdSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0Fm2MNVdwcARMDwXVaNJwcy1
G182BhnFhv7pDmqs4EFGlPvkG9oA02gBKeddJd7wcngcIH1cbpS64iG4r9d5R6OB
8TCB7jASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4E
FgQUfHj4bzyvo4unHysGt+pNa0XsBaIwHwYDVR0jBBgwFoAUfHj4bzyvo4unHysG
t+pNa0XsBaIwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL3VzZXJzLnVvYS5nci9+
cHN0YW1hdG9wL2NhLWNybC5wZW0wIAYDVR0RBBkwF4YVaHR0cDovL3d3dy53YWxs
ZXQub3JnMCoGA1UdEgQjMCGGFWh0dHA6Ly93d3cud2FsbGV0LmNvbYIId3dXYWxs
ZXQwCgYIKoZIzj0EAwIDRwAwRAIgGMfgLwOXvEk0sD3nEtCuwkZRzX9vyYZ/hfg6
VPrJszACIHBsYf7toXfUFjr6y1nAJ/oXP9l/fWBDydcQIq+Vnfem
-----END CERTIFICATE-----`
];



describe("verifyX5C function", () => {
	beforeEach(() => {
		// Keep cert validity checks deterministic regardless of current date
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2025-10-01T00:00:00.000Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should verify successfully the chain", async () => {
		const result = await verifyX5C(x5c, trustedCertificates);
		assert(result === true);
	})

	it("should result in invalid chain", async () => {
		const result = await verifyX5C(x5c, [ trustedCertificates[1] ]); // include only the second
		assert(result === false);
	})
	it("accepts a wrapped explicitly trusted leaf with a trailing root", async () => {
		const leafPem = `-----BEGIN CERTIFICATE-----\n${x5c[0].match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----`;
		const root = trustedCertificates[0].replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, "");
		assert(await verifyX5C([x5c[0], root], [leafPem]) === true);
	});

	it("accepts an explicitly trusted leaf regardless of PEM wrapping", async () => {
		const leafPem = `-----BEGIN CERTIFICATE-----\r\n${x5c[0].match(/.{1,64}/g)!.join("\r\n")}\r\n-----END CERTIFICATE-----`;
		assert(await verifyX5C(x5c, [leafPem]) === true);
	});

	it("rejects an expired explicitly trusted leaf", async () => {
		vi.setSystemTime(new Date("2027-01-01T00:00:00Z"));
		assert(await verifyX5C(x5c, [`-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`]) === false);
	});

	it("rejects a certificate with a modified signature under a trusted CA", async () => {
		const bytes = Uint8Array.from(atob(x5c[0]), c => c.charCodeAt(0));
		bytes[bytes.length - 1] ^= 1;
		const altered = btoa(String.fromCharCode(...bytes));
		assert(await verifyX5C([altered], trustedCertificates) === false);
	});

	it("rejects malformed certificates", async () => {
		assert(await verifyX5C(["invalid"], trustedCertificates) === false);
	});

	it("preserves acceptance of an empty chain", async () => {
		assert(await verifyX5C([], trustedCertificates) === true);
		assert(await verifyX5C([], []) === true);
	});

	it("accepts a full chain anchored in the configured CA", async () => {
		const root = trustedCertificates[0].replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, "");
		assert(await verifyX5C([x5c[0], root], [trustedCertificates[0]]) === true);
	});

	it("does not trust an issuer merely because its leaf is trusted", async () => {
		const root = trustedCertificates[0].replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, "");
		const leafPem = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
		assert(await verifyX5C([root], [leafPem]) === false);
		assert(await verifyX5C([x5c[0]], []) === false);
	});

	it("rejects a not-yet-valid explicitly trusted leaf", async () => {
		vi.setSystemTime(new Date("2025-01-01T00:00:00Z"));
		assert(await verifyX5C(x5c, [`-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`]) === false);
	});

	it("rejects a different leaf signed by the same issuer as a trusted leaf", async () => {
		const algorithm = { name: "ECDSA", namedCurve: "P-256" };
		const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
		const validity = {
			notBefore: new Date("2025-01-01T00:00:00Z"),
			notAfter: new Date("2030-01-01T00:00:00Z"),
			signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
		};
		const root = await X509CertificateGenerator.createSelfSigned({
			...validity, name: "CN=Test issuer", keys,
			extensions: [new BasicConstraintsExtension(true, undefined, true)],
		}, crypto);
		const createLeaf = async (name: string) => {
			const leafKeys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
			return X509CertificateGenerator.create({
				...validity, subject: name, issuer: "CN=Test issuer",
				publicKey: leafKeys.publicKey, signingKey: keys.privateKey,
			}, crypto);
		};
		const trusted = await createLeaf("CN=Trusted wallet");
		const other = await createLeaf("CN=Other wallet");
		assert(await verifyX5C([trusted.toString("base64"), root.toString("base64")], [trusted.toString("pem")]) === true);
		assert(await verifyX5C([other.toString("base64"), root.toString("base64")], [root.toString("pem")]) === true);
		assert(await verifyX5C([other.toString("base64"), root.toString("base64")], [trusted.toString("pem")]) === false);
	});

})
