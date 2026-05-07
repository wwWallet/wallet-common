import { VctDocumentProvider } from "../core";
import { defaultHttpClient } from "../defaultHttpClient";
import { getSdJwtVcMetadata } from "./getSdJwtVcMetadata";

export type sriAlgorithm = 'sha256' | 'sha384' | 'sha512';

export type SubtleAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

export const sriToSubtleAlgorithm: Record<sriAlgorithm, SubtleAlgorithm> = {
	sha256: 'SHA-256',
	sha384: 'SHA-384',
	sha512: 'SHA-512',
};

export const subtleToSriAlgorithm: Record<SubtleAlgorithm, sriAlgorithm> = {
	'SHA-256': 'sha256',
	'SHA-384': 'sha384',
	'SHA-512': 'sha512',
};

export async function calculateVctIntegritySRI(
	vctDocumentProvider: VctDocumentProvider,
	vctUrn: string,
	subtle: SubtleCrypto = crypto.subtle,
	algorithm: SubtleAlgorithm = 'SHA-256'
): Promise <string> {

	const metadata = await getSdJwtVcMetadata(vctDocumentProvider, crypto.subtle, defaultHttpClient, vctUrn, undefined);

	// if urn is http / https
	// then fetch data (should be application/json)
	// check if fetch data is successful
	// return calculateObjectSRI

	// else check our vct registry for this urn

	return '';
}

export async function calculateObjectSRI(
	subtle: SubtleCrypto,
	obj: Record<string, any>,
	algorithm: SubtleAlgorithm = 'SHA-256'
): Promise<string> {

	const jsonString = JSON.stringify(obj);
	const encoder = new TextEncoder();
	const data = encoder.encode(jsonString);

	return calculateDataSRI(subtle, data, algorithm);

}

export async function calculateDataSRI(
	subtle: SubtleCrypto,
	data: Uint8Array | Buffer,
	algorithm: SubtleAlgorithm = 'SHA-256'
): Promise<string> {
	const digest = await subtle.digest(algorithm, data);
	const hashArray = Array.from(new Uint8Array(digest));
	const hashBase64 = btoa(String.fromCharCode(...hashArray));
	return `${subtleToSriAlgorithm[algorithm]}-${hashBase64}`;
}

/**
 * Verifies that a given object matches the expected SRI integrity string.
 * @param obj - The object to verify
 * @param expectedIntegrity - The SRI string (e.g. 'sha256-<base64hash>')
 * @returns Promise resolving to true if valid, false otherwise
 */
export async function verifySRIFromObject(
	subtle: SubtleCrypto,
	obj: Record<string, any>,
	expectedIntegrity: string,
): Promise<boolean> {
	const [algorithm, expectedHash] = expectedIntegrity.split('-') as [sriAlgorithm, string];

	if (!algorithm || !expectedHash) {
		throw new Error('Invalid integrity string format');
	}

	const subtleAlgo = sriToSubtleAlgorithm[algorithm.toLowerCase() as sriAlgorithm];
	if (!subtleAlgo) {
		throw new Error(`Unsupported algorithm: ${algorithm}`);
	}

	const calculatedHash = await calculateObjectSRI(subtle, obj, subtleAlgo);

	return calculatedHash === expectedIntegrity;
}
