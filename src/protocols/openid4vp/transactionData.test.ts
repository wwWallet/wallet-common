import { describe, expect, it } from 'vitest';
import { HashAlgorithm } from '../../types';
import { QESAuthorizationTransactionData } from './transactionData';

describe('QES transaction data validation', () => {
	it('rejects when none of the supplied hashes matches the request', async () => {
		const result = await QESAuthorizationTransactionData().validateTransactionDataResponse('pid', {
			transaction_data_hashes: ['invalid-hash'],
			transaction_data_hashes_alg: [HashAlgorithm.sha_256],
		});

		expect(result).toEqual({ status: false, message: '' });
	});
});
