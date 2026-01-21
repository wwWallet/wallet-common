import { base64url } from 'jose';
import crypto from 'node:crypto';
import { fromBase64Url, toBase64Url } from "../../utils/util";


export const QESAuthorizationTransactionData = () => {
	const webcrypto = crypto.subtle;

	const generateTransactionDataRequestObject = async (descriptorId: string) => {
		return base64url.encode(JSON.stringify({
			type: 'https://cloudsignatureconsortium.org/2025/qes',
			credential_ids: [descriptorId],
			signatureQualifier: "eu_eidas_qes",
			transaction_data_hashes_alg: "sha-256",
			numSignatures: 1,
			processID: "random-process-id",
			documentDigests: [
				{
					hash: "some-hash-of-the-document",
					label: "Personal Loan Agreement",
					hashType: "sodr"
				}
			],
		}));
	}

	return {
		generateTransactionDataRequestObject,

		validateTransactionDataResponse: async (exprectedDescriptorId: string, params: { transaction_data_hashes: string[], transaction_data_hashes_alg?: string[] }) => {
			const expectedObjectB64U = await generateTransactionDataRequestObject(exprectedDescriptorId);
			const expectedObjectDecoded = fromBase64Url(expectedObjectB64U);
			for (const hashB64U of params.transaction_data_hashes) {
				if (!params.transaction_data_hashes_alg || params.transaction_data_hashes_alg.includes('sha-256')) { // sha256 case
					const calculatedHashOfExpectedObject = toBase64Url(await webcrypto.digest('SHA-256', expectedObjectDecoded));
					console.log("calculatedHash = ", calculatedHashOfExpectedObject);
					console.log("hashB64U = ", hashB64U);
					if (calculatedHashOfExpectedObject === hashB64U) {
						return { status: true, message: "User authorized the QTSP to create QES for the document \"Personal Loan Agreement\"" };
					}
				}
			}
			return { status: true, message: "" };
		}
	}
}

export const QCRequestTransactionData = () => {
	const webcrypto = crypto.subtle;

	const generateTransactionDataRequestObject = async (descriptorId: string) => {
		return base64url.encode(JSON.stringify({
			type: 'https://cloudsignatureconsortium.org/2025/qc-request',
			credential_ids: [descriptorId],
			QC_terms_conditions_uri: "https://qtsp.example.com/policies/terms_and_conditions.pdf",
			QC_hash: "ohxKcClPp/J1dI1iv5x519BpjduGZC794x4ABFeb+Ds=",
			QC_hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
			transaction_data_hashes_alg: "sha-256"
		}));
	}

	return {
		generateTransactionDataRequestObject,

		validateTransactionDataResponse: async (exprectedDescriptorId: string, params: { transaction_data_hashes: string[], transaction_data_hashes_alg?: string[] }) => {
			const expectedObjectB64U = await generateTransactionDataRequestObject(exprectedDescriptorId);
			const expectedObjectDecoded = fromBase64Url(expectedObjectB64U);
			for (const hashB64U of params.transaction_data_hashes) {
				if (!params.transaction_data_hashes_alg || params.transaction_data_hashes_alg.includes('sha-256')) { // sha256 case
					const calculatedHashOfExpectedObject = toBase64Url(await webcrypto.digest('SHA-256', expectedObjectDecoded));
					console.log("calculatedHash = ", calculatedHashOfExpectedObject);
					console.log("hashB64U = ", hashB64U);
					if (calculatedHashOfExpectedObject === hashB64U) {
						return { status: true, message: "User attested the creation of Qualified Certificates" };
					}
				}
			}
			return { status: false, message: "" };
		}
	}
}

export const TransactionData = (transactionDataType: 'https://cloudsignatureconsortium.org/2025/qes' | 'https://cloudsignatureconsortium.org/2025/qc-request') => {
	switch(transactionDataType) {
		case "https://cloudsignatureconsortium.org/2025/qes":
			return QESAuthorizationTransactionData();
		case "https://cloudsignatureconsortium.org/2025/qc-request":
			return QCRequestTransactionData();
		default:
			return null;
	}
}
