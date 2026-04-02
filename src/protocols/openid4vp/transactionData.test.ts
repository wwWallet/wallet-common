import { describe, it, expect } from 'vitest';
import { TransactionDataRequestObject, parseTransactionData } from './transactionData';
import { toBase64Url } from '../../utils/util';

describe('TransactionDataRequestObject schema', () => {
	describe('transaction_data_hashes_alg flexibility', () => {
		it('should accept transaction_data_hashes_alg as string "sha-256"', () => {
			const input = {
				type: 'qes_authorization',
				credential_ids: ['cred1'],
				transaction_data_hashes_alg: 'sha-256',
				documentDigests: [{ label: 'doc1' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
		});

		it('should accept transaction_data_hashes_alg as array ["sha-256"]', () => {
			const input = {
				type: 'qes_authorization',
				credential_ids: ['cred1'],
				transaction_data_hashes_alg: ['sha-256'],
				documentDigests: [{ label: 'doc1' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
		});

		it('should reject transaction_data_hashes_alg with unsupported algorithm', () => {
			const input = {
				type: 'qes_authorization',
				credential_ids: ['cred1'],
				transaction_data_hashes_alg: 'sha-512',
				documentDigests: [{ label: 'doc1' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(false);
		});
	});

	describe('optional fields', () => {
		it('should accept qes_authorization without signatureQualifier', () => {
			const input = {
				type: 'qes_authorization',
				credential_ids: ['cred1'],
				transaction_data_hashes_alg: 'sha-256',
				documentDigests: [{ label: 'doc1' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
		});

		it('should accept qes_authorization with signatureQualifier', () => {
			const input = {
				type: 'qes_authorization',
				credential_ids: ['cred1'],
				signatureQualifier: 'eu_eidas_qes',
				transaction_data_hashes_alg: 'sha-256',
				documentDigests: [{ label: 'doc1' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.signatureQualifier).toBe('eu_eidas_qes');
			}
		});

		it('should accept documentDigests without hashAlgorithmOID', () => {
			const input = {
				type: 'qes_authorization',
				credential_ids: ['cred1'],
				transaction_data_hashes_alg: 'sha-256',
				documentDigests: [{ label: 'doc1', hash: 'abc123' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
		});
	});

	describe('unknown keys handling', () => {
		it('should accept and strip unknown top-level keys', () => {
			const input = {
				type: 'qes_authorization',
				credential_ids: ['cred1'],
				transaction_data_hashes_alg: 'sha-256',
				documentDigests: [{ label: 'doc1' }],
				purpose: 'signing',
				timestamp: '2026-04-02T00:00:00Z',
				transaction_id: 'tx123',
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
			if (result.success) {
				// Unknown keys should be stripped (not propagated)
				expect('purpose' in result.data).toBe(false);
				expect('timestamp' in result.data).toBe(false);
				expect('transaction_id' in result.data).toBe(false);
			}
		});
	});

	describe('CSC QES type', () => {
		it('should accept CSC QES transaction data with array alg', () => {
			const input = {
				type: 'https://cloudsignatureconsortium.org/2025/qes',
				credential_ids: ['cred1'],
				transaction_data_hashes_alg: ['sha-256'],
				documentDigests: [{ label: 'Personal Loan Agreement' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
		});

		it('should accept CSC QES with optional fields', () => {
			const input = {
				type: 'https://cloudsignatureconsortium.org/2025/qes',
				credential_ids: ['cred1'],
				signatureQualifier: 'eu_eidas_qes',
				numSignatures: 1,
				processID: 'proc-123',
				transaction_data_hashes_alg: 'sha-256',
				documentDigests: [{ label: 'doc', hash: 'abc', hashType: 'sodr' }],
			};
			const result = TransactionDataRequestObject.safeParse(input);
			expect(result.success).toBe(true);
		});
	});
});

describe('parseTransactionData', () => {
	const encode = (obj: object) => toBase64Url(new TextEncoder().encode(JSON.stringify(obj)));

	it('should parse valid transaction data with string alg', () => {
		const td = {
			type: 'qes_authorization',
			credential_ids: ['desc1'],
			transaction_data_hashes_alg: 'sha-256',
			documentDigests: [{ label: 'doc1' }],
		};
		const dcql = { credentials: [{ id: 'desc1' }] };
		const result = parseTransactionData([encode(td)], dcql);
		expect(result).not.toBeNull();
		expect(result).toHaveLength(1);
		expect(result![0].parsed.type).toBe('qes_authorization');
	});

	it('should parse valid transaction data with array alg', () => {
		const td = {
			type: 'qes_authorization',
			credential_ids: ['desc1'],
			transaction_data_hashes_alg: ['sha-256'],
			documentDigests: [{ label: 'doc1' }],
		};
		const dcql = { credentials: [{ id: 'desc1' }] };
		const result = parseTransactionData([encode(td)], dcql);
		expect(result).not.toBeNull();
		expect(result).toHaveLength(1);
	});

	it('should parse transaction data with extra fields (ITP testbed format)', () => {
		const td = {
			type: 'qes_authorization',
			credential_ids: ['desc1'],
			transaction_data_hashes_alg: ['sha-256'],
			documentDigests: [{ label: 'doc1' }],
			purpose: 'signing',
			timestamp: '2026-04-02T00:00:00Z',
			transaction_id: 'tx123',
		};
		const dcql = { credentials: [{ id: 'desc1' }] };
		const result = parseTransactionData([encode(td)], dcql);
		expect(result).not.toBeNull();
		expect(result).toHaveLength(1);
	});

	it('should return null for invalid transaction data', () => {
		const td = {
			type: 'unknown_type',
			credential_ids: ['desc1'],
		};
		const dcql = { credentials: [{ id: 'desc1' }] };
		const result = parseTransactionData([encode(td)], dcql);
		expect(result).toBeNull();
	});

	it('should return null when credential_ids reference non-existent descriptors', () => {
		const td = {
			type: 'qes_authorization',
			credential_ids: ['nonexistent'],
			transaction_data_hashes_alg: 'sha-256',
			documentDigests: [{ label: 'doc1' }],
		};
		const dcql = { credentials: [{ id: 'desc1' }] };
		const result = parseTransactionData([encode(td)], dcql);
		expect(result).toBeNull();
	});
});
