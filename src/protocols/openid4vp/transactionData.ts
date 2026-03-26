import { base64url } from 'jose';
import crypto from 'node:crypto';
import { z } from "zod";
import { fromBase64Url, toBase64Url } from "../../utils/util";
import { TransactionDataResponseGenerator, TransactionDataResponseGeneratorParams } from './types';
import { DigestHashAlgorithm, HashAlgorithm } from '../../types';

const baseDocumentObjectSchema = z.object({
	label: z.string().optional(),
	circumstantialData: z.string().optional()
});

const accessControlMethodObjectSchema = z.discriminatedUnion("type", [
	z.object({
		type: z.literal("public")
	}).strict(),
	z.object({
		type: z.literal("OTP"),
		oneTimePassword: z.string().min(1)
	}).strict()
]);

const documentDataObjectSchema = baseDocumentObjectSchema.extend({
	document: z.string(),
	documentType: z.enum(["sod", "sfd"]).default("sod"),
}).strict();

const documentReferenceObjectSchema = baseDocumentObjectSchema.extend({
	access: accessControlMethodObjectSchema.optional(),
	href: z.string().url(),
	checksum: z.object({
		value: z.string(),
		algorithmOID: z.string()
	}).optional(),
}).strict();

const signatureFormatEnum = z.enum(["C", "X", "P", "J"]);

const conformanceLevelEnum = z.enum([
	"AdES-B-B",
	"AdES-B-T",
	"AdES-B-LT",
	"AdES-B-LTA",
	"AdES-B",
	"AdES-T",
	"AdES-LT",
	"AdES-LTA",
]);

const signedEnvelopePropertyEnum = z.enum([
	// CAdES / JAdES
	"Detached",
	"Attached",
	"Parallel",
	// PAdES
	"Certification",
	"Revision",
	// XAdES
	"Enveloped",
	"Enveloping",
]);

const attributeObjectSchema = z.object({
	attribute_name: z.string().min(1),
	attribute_value: z.string().optional()
});

const adesParametersObjectSchema = z.object({
	signature_format: signatureFormatEnum.optional(),
	conformance_level: conformanceLevelEnum.optional(),
	signed_envelope_property: signedEnvelopePropertyEnum.optional(),
	signed_props: z.array(attributeObjectSchema).optional(),
	referenceUri: z.string().url().optional()
});

const signatureRequestBaseSchema = z.object({
	responseURI: z.string().url().optional(),
	signatureQualifier: z.string().min(1).optional(),
}).merge(adesParametersObjectSchema);


const signatureRequestObjectSchema = z.union([
	signatureRequestBaseSchema.merge(documentDataObjectSchema),
	signatureRequestBaseSchema.merge(documentReferenceObjectSchema),
]);

export const TransactionDataRequestObject = z.discriminatedUnion("type", [
	z.object({
		type: z.literal("urn:wwwallet:example_transaction_data_type"),
		credential_ids: z.array(z.string()),
	}).strict(),

	z.object({
		type: z.literal("qes_authorization"),
		credential_ids: z.array(z.string()),
		signatureQualifier: z.string(),
		transaction_data_hashes_alg: z.array(z.literal(HashAlgorithm.sha_256)),
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
		transaction_data_hashes_alg: z.array(z.literal(HashAlgorithm.sha_256)),
	}).strict(),

	z.object({
		type: z.literal("https://cloudsignatureconsortium.org/2025/qes"),
		credential_ids: z.array(z.string()),
		signatureQualifier: z.string().min(1),
		signatureRequests: z.array(signatureRequestObjectSchema)
	}).strict(),

	z.object({
		type: z.literal("https://cloudsignatureconsortium.org/2025/qc-request"),
		credential_ids: z.array(z.string()),
		QC_terms_conditions_uri: z.string().optional(),
		QC_hash: z.string().optional(),
		QC_hashAlgorithmOID: z.string().optional(),
		transaction_data_hashes_alg: z.array(z.literal(HashAlgorithm.sha_256)),
	}).strict(),
]);

export type TransactionDataRequest = z.infer<typeof TransactionDataRequestObject>;

export type ParsedTransactionDataType = {
	transaction_data_b64u: string;
	parsed: TransactionDataRequest;
};

export function parseTransactionData(
	transaction_data: string[],
	dcql_query: Record<string, unknown>
): ParsedTransactionDataType[] | null {
	try {
		let validCredentialIds: string[] | null = null;

		if ((dcql_query as any)?.credentials instanceof Array) {
			validCredentialIds = (dcql_query as any).credentials.map(
				(credential: { id: string }) => credential.id
			);
		}

		const parsedTransactionData = transaction_data.map((td) => {
			const decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(td)));
			const parsed = TransactionDataRequestObject.parse(decoded);
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
	const digest = await webcrypto.digest(DigestHashAlgorithm.SHA_256, data);
	return toBase64Url(digest);
}

export const TransactionDataResponse = ({ descriptor_id, dcql_query }: TransactionDataResponseGeneratorParams): TransactionDataResponseGenerator => {
	return {
		generateTransactionDataResponse: async (transaction_data: string[]) => {
			const parsedTd = parseTransactionData(transaction_data, dcql_query);
			if (parsedTd === null) {
				return [null, new Error("invalid_transaction_data")];
			}
			for (const td of parsedTd) {
				if (td.parsed.credential_ids.includes(descriptor_id)) {
					return [{
						transaction_data_hashes: [await convertTransactionDataB65uToHash(td.transaction_data_b64u)],
						transaction_data_hashes_alg: [HashAlgorithm.sha_256],
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
			signatureRequests: [
				{
					document: "some-hash-of-the-document",
					label: "Personal Loan Agreement",
					documentType: "sod"
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
				console.log(params.transaction_data_hashes_alg);
				if (!params.transaction_data_hashes_alg || params.transaction_data_hashes_alg.includes(HashAlgorithm.sha_256)) { // sha256 case
					const calculatedHashOfExpectedObject = toBase64Url(await webcrypto.digest(DigestHashAlgorithm.SHA_256, expectedObjectDecoded));
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
			transaction_data_hashes_alg: [HashAlgorithm.sha_256]
		}));
	}

	return {
		generateTransactionDataRequestObject,

		validateTransactionDataResponse: async (exprectedDescriptorId: string, params: { transaction_data_hashes: string[], transaction_data_hashes_alg?: string[] }) => {
			const expectedObjectB64U = await generateTransactionDataRequestObject(exprectedDescriptorId);
			const expectedObjectDecoded = fromBase64Url(expectedObjectB64U);
			for (const hashB64U of params.transaction_data_hashes) {
				if (!params.transaction_data_hashes_alg || params.transaction_data_hashes_alg.includes(HashAlgorithm.sha_256)) { // sha256 case
					const calculatedHashOfExpectedObject = toBase64Url(await webcrypto.digest(DigestHashAlgorithm.SHA_256, expectedObjectDecoded));
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
