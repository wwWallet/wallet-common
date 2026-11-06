import crypto from 'crypto';
import { describe, expect, it } from 'vitest';
import { err, ok, VctDocumentProvider, VctResolutionErrors } from '../core';
import { HttpClient } from '../interfaces';
import { TypeMetadata } from '../schemas';
import { getSdJwtVcMetadata } from './getSdJwtVcMetadata';

const childVct = 'urn:test:child';
const parentVct = 'urn:test:parent';

const noHttpClient: HttpClient = {
	get: async () => {
		throw new Error('HTTP must not be used for URN Type Metadata');
	},
	post: async () => {
		throw new Error('HTTP must not be used for URN Type Metadata');
	},
};

const resolve = async (documents: Record<string, TypeMetadata>, vct = childVct) => {
	const provider: VctDocumentProvider = {
		getVctMetadataDocument: async (metadataId) => {
			const metadata = documents[metadataId];
			return metadata ? ok(metadata) : err(VctResolutionErrors.NotFound);
		},
	};

	return getSdJwtVcMetadata(provider, crypto.subtle, noHttpClient, vct, undefined);
};

const parentMetadata = (claim: TypeMetadata['claims'][number]): TypeMetadata => ({
	vct: parentVct,
	claims: [claim],
});

const childMetadata = (claim?: TypeMetadata['claims'][number]): TypeMetadata => ({
	vct: childVct,
	extends: parentVct,
	claims: claim ? [claim] : [],
});

describe('getSdJwtVcMetadata inheritance validation', () => {
	it('rejects root and parent documents whose vct does not match the retrieval reference', async () => {
		await expect(resolve({ [childVct]: { vct: 'urn:test:wrong' } })).resolves.toEqual({
			error: 'TypeMetadataVctMismatch',
		});

		await expect(
			resolve({
				[childVct]: childMetadata(),
				[parentVct]: { vct: 'urn:test:wrong' },
			}),
		).resolves.toEqual({ error: 'TypeMetadataVctMismatch' });
	});

	it.each([
		['always', 'allowed'],
		['always', 'never'],
		['never', 'allowed'],
		['never', 'always'],
	] as const)('rejects changing inherited sd %s to %s', async (parentSd, childSd) => {
		const result = await resolve({
			[parentVct]: parentMetadata({ path: ['name'], sd: parentSd }),
			[childVct]: childMetadata({ path: ['name'], sd: childSd }),
		});

		expect(result).toEqual({ error: 'InvalidTypeMetadataInheritance' });
	});

	it('rejects changing an inherited mandatory claim to optional', async () => {
		const result = await resolve({
			[parentVct]: parentMetadata({ path: ['name'], mandatory: true }),
			[childVct]: childMetadata({ path: ['name'], mandatory: false }),
		});

		expect(result).toEqual({ error: 'InvalidTypeMetadataInheritance' });
	});

	it('allows an inherited allowed claim to become always and mandatory', async () => {
		const result = await resolve({
			[parentVct]: parentMetadata({ path: ['name'], sd: 'allowed' }),
			[childVct]: childMetadata({ path: ['name'], sd: 'always', mandatory: true }),
		});

		expect(result).not.toHaveProperty('error');
	});

	it('enforces restrictions inherited through multiple parents', async () => {
		const middleVct = 'urn:test:middle';
		const result = await resolve({
			[parentVct]: parentMetadata({ path: ['name'], sd: 'always' }),
			[middleVct]: { vct: middleVct, extends: parentVct },
			[childVct]: {
				vct: childVct,
				extends: middleVct,
				claims: [{ path: ['name'], sd: 'never' }],
			},
		});

		expect(result).toEqual({ error: 'InvalidTypeMetadataInheritance' });
	});
});
