/**
 * Verify a certificate using another certificate (CA)
 * @param {string} leafCertPem - The certificate to verify (PEM format)
 * @param {string} caCertPem - The CA certificate (PEM format)
 * @returns {Promise<boolean>}
 */
export declare function verifyCertificate(leafCertPem: string, trustedCerts: string[]): Promise<boolean>;
//# sourceMappingURL=verifyCertificate.d.ts.map