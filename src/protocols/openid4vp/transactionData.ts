import { base64url } from 'jose';
import crypto from 'node:crypto';
import { z } from "zod";
import { fromBase64Url, toBase64Url } from "../../utils/util";

const sha256 = z.literal("sha-256");

export const TransactionDataRequestObject = z.discriminatedUnion("type", [
	z.object({
		type: z.literal("urn:wwwallet:example_transaction_data_type"),
		credential_ids: z.array(z.string()),
	}).strict(),

	z.object({
		type: z.literal("qes_authorization"),
		credential_ids: z.array(z.string()),
		signatureQualifier: z.string(),
		transaction_data_hashes_alg: sha256,
		documentDigests: z.array(z.object({
			hash: z.string().optional(),
			label: z.string(),
			hashAlgorithmOID: z.string(),
		})),
	}).strict(),

	z.object({
		type: z.literal("qcert_creation_acceptance"),
		credential_ids: z.array(z.string()),
		QC_terms_conditions_uri: z.string().optional(),
		QC_hash: z.string().optional(),
		QC_hashAlgorithmOID: z.string().optional(),
		transaction_data_hashes_alg: sha256,
	}).strict(),

	z.object({
		type: z.literal("https://cloudsignatureconsortium.org/2025/qes"),
		credential_ids: z.array(z.string()),
		numSignatures: z.number().optional(),
		signatureQualifier: z.string(),
		transaction_data_hashes_alg: sha256,
		documentDigests: z.array(z.object({
			hash: z.string().optional(),
			label: z.string(),
			hashType: z.string(),
		})),
		processID: z.string().optional(),
	}).strict(),

	z.object({
		type: z.literal("https://cloudsignatureconsortium.org/2025/qc-request"),
		credential_ids: z.array(z.string()),
		QC_terms_conditions_uri: z.string().optional(),
		QC_hash: z.string().optional(),
		QC_hashAlgorithmOID: z.string().optional(),
		transaction_data_hashes_alg: sha256,
	}).strict(),
]);

export type TransactionDataRequest = z.infer<typeof TransactionDataRequestObject>;

export type ParsedTransactionDataCore = {
	transaction_data_b64u: string;
	parsed: TransactionDataRequest;
};

export function parseTransactionDataCore(
	transaction_data: string[],
	dcql_query: Record<string, unknown>
): ParsedTransactionDataCore[] | null {
	try {
		let validCredentialIds: string[] | null = null;

		if ((dcql_query as any)?.credentials instanceof Array) {
			validCredentialIds = (dcql_query as any).credentials.map(
				(credential: { id: string }) => credential.id
			);
		}

		const parsedTransactionData = transaction_data.map((td) => {
			const parsed = TransactionDataRequestObject.parse(
				JSON.parse(new TextDecoder().decode(fromBase64Url(td)))
			);
			return {
				transaction_data_b64u: td,
				parsed,
			};
		});
		for (const td of parsedTransactionData) {
			if (td.parsed.credential_ids && validCredentialIds) {
				for (const cred_id of td.parsed.credential_ids) {
					if (!validCredentialIds.includes(cred_id)) {
						throw new Error("Transaction data includes invalid credential ids that don't exist in the definition");
					}
				}
			}
		}
		return parsedTransactionData;
	}
	catch (e) {
		console.error(e);
		return null;
	}
}

export async function convertTransactionDataB65uToHash(x: string) {
	const data = fromBase64Url(x);
	const webcrypto = globalThis.crypto?.subtle ?? crypto.subtle;
	const digest = await webcrypto.digest('SHA-256', data);
	return toBase64Url(digest);
}

export type TransactionDataResponseParams = {
	transaction_data_hashes: string[],
	transaction_data_hashes_alg: string[],
};

export interface TransactionDataResponseGenerator {
	generateTransactionDataResponse(transaction_data: string[]): Promise<[TransactionDataResponseParams | null, Error | null]>;
}

export type TransactionDataResponseGeneratorParams = {
	descriptor_id: string;
	dcql_query: Record<string, unknown>;
};

export const TransactionDataResponse = ({ descriptor_id, dcql_query }: TransactionDataResponseGeneratorParams): TransactionDataResponseGenerator => {
	return {
		generateTransactionDataResponse: async (transaction_data: string[]) => {
			const parsedTd = parseTransactionDataCore(transaction_data, dcql_query);
			if (parsedTd === null) {
				return [null, new Error("invalid_transaction_data")];
			}
			for (const td of parsedTd) {
				if (td.parsed.credential_ids.includes(descriptor_id)) {
					return [{
						transaction_data_hashes: [await convertTransactionDataB65uToHash(td.transaction_data_b64u)],
						transaction_data_hashes_alg: ["sha-256"],
					}, null]
				}
			}
			return [null, new Error("Couldn't generate transaction data response")];
		},
	}
}


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
