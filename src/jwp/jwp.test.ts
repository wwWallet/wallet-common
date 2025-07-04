import { assert, describe, it } from "vitest";

import { getCipherSuite, PointG1 } from "../bbs";
import { fromBase64Url, toBase64Url, toHex } from "../utils/util";
import { asyncAssertThrows } from "../testutil";
import { assembleIssuedJwp, assemblePresentationJwp, confirm, exportHolderPrivateJwk, exportIssuerPrivateJwk, importHolderPublicJwk, importIssuerPublicJwk, issueBbs, issueSplitBbs, parseIssuedJwp, parsePresentedJwp, presentBbs, presentSplitBbs, verify } from ".";


describe("JWK", () => {
	it("encodes and decodes BBS issuer public keys correctly.", async () => {
		const suiteId = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
		const { KeyGen, params: { curves: { G2 } } } = getCipherSuite(suiteId);
		const SK = await KeyGen(crypto.getRandomValues(new Uint8Array(32)), new TextEncoder().encode('JWP test Split-BBS'), null);
		const PK = G2.Point.BASE.multiply(SK).toBytes();
		const jwk = exportIssuerPrivateJwk(SK, 'BBS');
		const restoredPk = importIssuerPublicJwk(jwk, 'BBS');
		assert.equal(toHex(restoredPk), toHex(PK));
	});

	it("encodes and decodes BBS holder public keys correctly.", async () => {
		const suiteId = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
		const { KeyGen, params: { curves: { G1 } } } = getCipherSuite(suiteId);
		const dsk = await KeyGen(crypto.getRandomValues(new Uint8Array(32)), new TextEncoder().encode('JWP test Split-BBS dsk'), null);
		const pk = G1.Point.BASE.multiply(dsk);
		const jwk = exportHolderPrivateJwk(dsk, 'BBS');
		const restoredPk = importHolderPublicJwk(jwk, 'BBS');
		assert.equal(toHex(restoredPk.toBytes()), toHex(pk.toBytes()));
	});
});

describe("JWP", () => {
	it("preserves zero-length payloads and proofs in issued JWPs.", () => {
		const jwp = assembleIssuedJwp({ alg: '' }, [new Uint8Array([])], [new Uint8Array([])]);
		const { parsed } = parseIssuedJwp(jwp);
		assert.exists(parsed.payloads);
		assert.equal(parsed.payloads.length, 1);
		assert.equal(parsed.payloads[0].byteLength, 0);
		assert.exists(parsed.proof);
		assert.equal(parsed.proof.length, 1);
		assert.equal(parsed.proof[0].byteLength, 0);
	});

	describe("preserves zero-length payloads and proofs in presented JWPs", () => {
		it("when issued JWP has one payload.", () => {
			const issuedJwp = assembleIssuedJwp({ alg: '' }, [new Uint8Array([])], [new Uint8Array([])]);
			const jwp = assemblePresentationJwp(issuedJwp, { alg: '' }, [0], [new Uint8Array([])]);
			const { parsed } = parsePresentedJwp(jwp);
			assert.exists(parsed.payloads);
			assert.equal(parsed.payloads.length, 1);
			assert.equal(parsed.payloads[0]?.byteLength, 0);
			assert.exists(parsed.proof);
			assert.equal(parsed.proof.length, 1);
			assert.equal(parsed.proof[0].byteLength, 0);
		});

		it("when issued JWP has two payloads and one is disclosed.", () => {
			const issuedJwp = assembleIssuedJwp({ alg: '' }, [new Uint8Array([]), new Uint8Array([])], [new Uint8Array([]), new Uint8Array([])]);
			const jwp = assemblePresentationJwp(issuedJwp, { alg: '' }, [0], [new Uint8Array([]), new Uint8Array([])]);
			const { parsed } = parsePresentedJwp(jwp);
			assert.exists(parsed.payloads);
			assert.equal(parsed.payloads.length, 2);
			assert.equal(parsed.payloads[0]?.byteLength, 0);
			assert.equal(parsed.payloads[1], null);
			assert.exists(parsed.proof);
			assert.equal(parsed.proof.length, 2);
			assert.equal(parsed.proof[0].byteLength, 0);
			assert.equal(parsed.proof[1].byteLength, 0);
		});
	});

	describe("preserves absent payloads and proofs in presented JWPs", () => {
		it("when issued JWP has one payload which is not disclosed.", () => {
			const issuedJwp = assembleIssuedJwp({ alg: '' }, [new Uint8Array([])], [new Uint8Array([])]);
			const jwp = assemblePresentationJwp(issuedJwp, { alg: '' }, [], []);
			const { parsed } = parsePresentedJwp(jwp);
			assert.exists(parsed.payloads);
			assert.equal(parsed.payloads.length, 1);
			assert.equal(parsed.payloads[0], null);
			assert.exists(parsed.proof);
			assert.equal(parsed.proof.length, 0);
		});

		it("when issued JWP has two payloads and one is disclosed.", () => {
			const issuedJwp = assembleIssuedJwp({ alg: '' }, [new Uint8Array([]), new Uint8Array([])], [new Uint8Array([])]);
			const jwp = assemblePresentationJwp(issuedJwp, { alg: '' }, [1], []);
			const { parsed } = parsePresentedJwp(jwp);
			assert.exists(parsed.payloads);
			assert.equal(parsed.payloads.length, 2);
			assert.equal(parsed.payloads[0], null);
			assert.equal(parsed.payloads[1]?.byteLength, 0);
			assert.exists(parsed.proof);
			assert.equal(parsed.proof.length, 0);
		});
	});

	describe("With BBS", async () => {

		const suiteId = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
		const { KeyGen, SkToPk } = getCipherSuite(suiteId);
		const SK = await KeyGen(crypto.getRandomValues(new Uint8Array(32)), new TextEncoder().encode('JWP test BBS'), null);
		const PK = SkToPk(SK);
		const issuerJwk = exportIssuerPrivateJwk(SK, 'BBS');

		describe("can issue and confirm a JWP", () => {
			it("with a single payload.", async () => {
				const issuedJwp = await issueBbs(
					SK, PK,
					{ alg: 'BBS', aud: 'JWP test' },
					[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
				);

				const valid = await confirm(issuerJwk, issuedJwp);
				assert.equal(valid, true);
				assert.equal(new TextDecoder().decode(fromBase64Url(issuedJwp.split(".")[1])), 'Kom ihåg att du aldrig får snyta dig i mattan!');
			});

			it("with multiple payloads.", async () => {
				const randomMessage = crypto.getRandomValues(new Uint8Array(32));
				const issuedJwp = await issueBbs(
					SK, PK,
					{ alg: 'BBS', aud: 'JWP test' },
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						randomMessage,
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);

				const valid = await confirm(issuerJwk, issuedJwp);
				assert.equal(valid, true);
				const payloads = issuedJwp.split(".")[1].split('~').map(fromBase64Url);
				assert.equal(new TextDecoder().decode(payloads[0]), 'Kom ihåg att du aldrig får snyta dig i mattan!');
				assert.equal(toHex(payloads[1]), toHex(randomMessage));
				assert.deepEqual(
					JSON.parse(new TextDecoder().decode(payloads[2])),
					{ some: 'JSON', obj: ['foo', 42] },
				);
			});
		});

		describe("refuses to issue a JWP", () => {
			it("with no payloads.", async () => {
				await asyncAssertThrows(
					() =>
						issueBbs(
							SK, PK,
							{ alg: 'BBS', aud: 'JWP test' },
							[],
						),
					"",
				);
			});
		});

		describe("rejects an issued JWP", async () => {
			const issuedJwp = await issueBbs(
				SK, PK,
				{ alg: 'BBS', aud: 'JWP test' },
				[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
			);

			it("with a modified header.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.slice(1)), "");
			});

			it("without signature.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.split(".").slice(0, 2).join(".")), "");
			});

			it("with truncated signature.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.slice(0, issuedJwp.length - 4)), "");
			});

			it("with the payloads omitted.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.split(".").map((s, i) => i === 1 ? '' : s).join(".")), "");
			});

			it("with modified payloads.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.split(".").map((s, i) => i === 1 ? toBase64Url(new TextEncoder().encode('foo')) : s).join(".")), "");
			});
		});

		describe("can create and verify a JWP presentation", () => {
			it("with a single payload, disclosed.", async () => {
				const issuedJwp = await issueBbs(
					SK, PK,
					{ alg: 'BBS', aud: 'JWP test' },
					[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
				);
				const presentedJwp = await presentBbs(
					PK,
					issuedJwp,
					{ alg: 'BBS', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[0],
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				assert.equal(
					new TextDecoder().decode(fromBase64Url(presentedJwp.split(".")[2])),
					'Kom ihåg att du aldrig får snyta dig i mattan!',
				);
			});

			it("with a single payload, not disclosed.", async () => {
				const issuedJwp = await issueBbs(
					SK, PK,
					{ alg: 'BBS', aud: 'JWP test' },
					[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
				);
				const presentedJwp = await presentBbs(
					PK,
					issuedJwp,
					{ alg: 'BBS', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[],
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				assert.equal(presentedJwp.split(".")[2], '');
			});

			it("with multiple payloads, all disclosed.", async () => {
				const randomMessage = crypto.getRandomValues(new Uint8Array(32));
				const issuedJwp = await issueBbs(
					SK, PK,
					{ alg: 'BBS', aud: 'JWP test' },
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						randomMessage,
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);
				const presentedJwp = await presentBbs(
					PK,
					issuedJwp,
					{ alg: 'BBS', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[0, 1, 2],
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				const payloads = presentedJwp.split(".")[2].split('~').map(fromBase64Url);
				assert.equal(new TextDecoder().decode(payloads[0]), 'Kom ihåg att du aldrig får snyta dig i mattan!');
				assert.equal(toHex(payloads[1]), toHex(randomMessage));
				assert.deepEqual(
					JSON.parse(new TextDecoder().decode(payloads[2])),
					{ some: 'JSON', obj: ['foo', 42] },
				);
			});

			it("with multiple payloads, some disclosed.", async () => {
				const randomMessage = crypto.getRandomValues(new Uint8Array(32));
				const issuedJwp = await issueBbs(
					SK, PK,
					{ alg: 'BBS', aud: 'JWP test' },
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						randomMessage,
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);
				const presentedJwp = await presentBbs(
					PK,
					issuedJwp,
					{ alg: 'BBS', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[0, 2],
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				const payloads = presentedJwp.split(".")[2].split('~').map(fromBase64Url);
				assert.equal(new TextDecoder().decode(payloads[0]), 'Kom ihåg att du aldrig får snyta dig i mattan!');
				assert.equal(toHex(payloads[1]), '');
				assert.deepEqual(
					JSON.parse(new TextDecoder().decode(payloads[2])),
					{ some: 'JSON', obj: ['foo', 42] },
				);
			});

			it("with multiple payloads, none disclosed.", async () => {
				const randomMessage = crypto.getRandomValues(new Uint8Array(32));
				const issuedJwp = await issueBbs(
					SK, PK,
					{ alg: 'BBS', aud: 'JWP test' },
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						randomMessage,
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);
				const presentedJwp = await presentBbs(
					PK,
					issuedJwp,
					{ alg: 'BBS', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[],
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				const payloads = presentedJwp.split(".")[2];
				assert.equal(payloads, '~~');
			});
		});

		describe("rejects a JWP presentation", async () => {
			const issuedJwp = await issueBbs(
				SK, PK,
				{ alg: 'BBS', aud: 'JWP test' },
				[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
			);
			const presentedJwp = await presentBbs(
				PK,
				issuedJwp,
				{ alg: 'BBS', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
				[0],
			);

			it("with a modified presentation header.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.slice(1)), "");
			});

			it("with a modified issuer header.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").map((s, i) => i === 1 ? s.slice(1) : s).join(".")), "");
			});

			it("without proof.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").slice(0, 3).join(".")), "");
			});

			it("with truncated proof.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.slice(0, presentedJwp.length - 4)), "");
			});

			it("with a disclosed payload omitted.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").map((s, i) => i === 2 ? '' : s).join(".")), "");
			});

			it("with a modified payload.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").map((s, i) => i === 2 ? toBase64Url(new TextEncoder().encode('foo')) : s).join(".")), "Expected JWP verification to fail with modified message");
			});
		});
	});

	describe("With Split-BBS", async () => {

		const suiteId = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
		const { KeyGen, SplitProofGenDevice, params: { curves: { G1, G2 } }  } = getCipherSuite(suiteId);
		const SK = await KeyGen(crypto.getRandomValues(new Uint8Array(32)), new TextEncoder().encode('JWP test Split-BBS'), null);
		const PK = G2.Point.BASE.multiply(SK).toBytes();
		const issuerJwk = exportIssuerPrivateJwk(SK, 'experimental/SplitBBSv2.1');
		const dsk = await KeyGen(crypto.getRandomValues(new Uint8Array(32)), new TextEncoder().encode('JWP test Split-BBS dsk'), null);
		const dpk = exportHolderPrivateJwk(dsk, 'experimental/SplitBBSv2.1');
		const deviceSign = (T2bar: PointG1, c_host: bigint) => SplitProofGenDevice(dsk, G1.Point.BASE, c_host, T2bar);

		describe("can issue and confirm a JWP", () => {
			it("with a single payload.", async () => {
				const issuedJwp = await issueSplitBbs(
					issuerJwk,
					{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
					dpk,
					[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
				);

				const valid = await confirm(issuerJwk, issuedJwp);
				assert.equal(valid, true);

				const [_header, payloads, proof] = issuedJwp.split('.');
				assert.deepEqual(payloads, toBase64Url(new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')));
				const [_signature, dpkOut] = proof.split('~');
				assert.deepEqual(dpkOut, toBase64Url(G1.Point.BASE.multiply(dsk).toBytes()));
			});

			it("with multiple payloads.", async () => {
				const issuedJwp = await issueSplitBbs(
					issuerJwk,
					{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
					dpk,
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						crypto.getRandomValues(new Uint8Array(32)),
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);

				const valid = await confirm(issuerJwk, issuedJwp);
				assert.equal(valid, true);

				const [_header, payloads, _proof] = issuedJwp.split('.');
				assert.equal(payloads.split('~').length, 3);
			});
		});

		describe("refuses to issue a JWP", () => {
			it("with no payloads.", async () => {
				await asyncAssertThrows(
					() =>
						issueSplitBbs(
							issuerJwk,
							{ alg: 'BBS', aud: 'JWP test' },
							dpk,
							[],
						),
					"",
				);
			});
		});

		describe("rejects an issued JWP", async () => {
			const issuedJwp = await issueSplitBbs(
				issuerJwk,
				{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
				dpk,
				[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
			);

			it("with a modified header.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.slice(1)), "");
			});

			it("without signature.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.split(".").slice(0, 2).join(".")), "");
			});

			it("with truncated signature.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.slice(0, issuedJwp.length - 4)), "");
			});

			it("with the payloads omitted.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.split(".").map((s, i) => i === 1 ? '' : s).join(".")), "");
			});

			it("with modified payloads.", async () => {
				await asyncAssertThrows(() => confirm(issuerJwk, issuedJwp.split(".").map((s, i) => i === 1 ? toBase64Url(new TextEncoder().encode('foo')) : s).join(".")), "");
			});
		});

		describe("can create and verify a JWP presentation", () => {
			it("with a single payload, disclosed.", async () => {
				const issuedJwp = await issueSplitBbs(
					issuerJwk,
					{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
					dpk,
					[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
				);
				const presentedJwp = await presentSplitBbs(
					issuerJwk,
					issuedJwp,
					{ alg: 'experimental/SplitBBSv2.1', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[0],
					deviceSign,
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				assert.equal(
					new TextDecoder().decode(fromBase64Url(presentedJwp.split(".")[2])),
					'Kom ihåg att du aldrig får snyta dig i mattan!',
				);
			});

			it("with a single payload, not disclosed.", async () => {
				const issuedJwp = await issueSplitBbs(
					issuerJwk,
					{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
					dpk,
					[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
				);
				const presentedJwp = await presentSplitBbs(
					issuerJwk,
					issuedJwp,
					{ alg: 'experimental/SplitBBSv2.1', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[],
					deviceSign,
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				assert.equal(presentedJwp.split(".")[2], '');
			});

			it("with multiple payloads, all disclosed.", async () => {
				const randomMessage = crypto.getRandomValues(new Uint8Array(32));
				const issuedJwp = await issueSplitBbs(
					issuerJwk,
					{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
					dpk,
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						randomMessage,
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);
				const presentedJwp = await presentSplitBbs(
					issuerJwk,
					issuedJwp,
					{ alg: 'experimental/SplitBBSv2.1', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[0, 1, 2],
					deviceSign,
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				const payloads = presentedJwp.split(".")[2].split('~').map(fromBase64Url);
				assert.equal(new TextDecoder().decode(payloads[0]), 'Kom ihåg att du aldrig får snyta dig i mattan!');
				assert.equal(toHex(payloads[1]), toHex(randomMessage));
				assert.deepEqual(
					JSON.parse(new TextDecoder().decode(payloads[2])),
					{ some: 'JSON', obj: ['foo', 42] },
				);
			});

			it("with multiple payloads, some disclosed.", async () => {
				const randomMessage = crypto.getRandomValues(new Uint8Array(32));
				const issuedJwp = await issueSplitBbs(
					issuerJwk,
					{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
					dpk,
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						randomMessage,
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);
				const presentedJwp = await presentSplitBbs(
					issuerJwk,
					issuedJwp,
					{ alg: 'experimental/SplitBBSv2.1', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[0, 2],
					deviceSign
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				const payloads = presentedJwp.split(".")[2].split('~').map(fromBase64Url);
				assert.equal(new TextDecoder().decode(payloads[0]), 'Kom ihåg att du aldrig får snyta dig i mattan!');
				assert.equal(toHex(payloads[1]), '');
				assert.deepEqual(
					JSON.parse(new TextDecoder().decode(payloads[2])),
					{ some: 'JSON', obj: ['foo', 42] },
				);
			});

			it("with multiple payloads, none disclosed.", async () => {
				const randomMessage = crypto.getRandomValues(new Uint8Array(32));
				const issuedJwp = await issueSplitBbs(
					issuerJwk,
					{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
					dpk,
					[
						new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!'),
						randomMessage,
						new TextEncoder().encode(JSON.stringify({ some: 'JSON', obj: ['foo', 42] })),
					],
				);
				const presentedJwp = await presentSplitBbs(
					issuerJwk,
					issuedJwp,
					{ alg: 'experimental/SplitBBSv2.1', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
					[],
					deviceSign,
				);

				const valid = await verify(PK, presentedJwp);
				assert.equal(valid, true);
				const payloads = presentedJwp.split(".")[2];
				assert.equal(payloads, '~~');
			});
		});

		describe("rejects a JWP presentation", async () => {
			const issuedJwp = await issueSplitBbs(
				issuerJwk,
				{ alg: 'experimental/SplitBBSv2.1', aud: 'JWP test' },
				dpk,
				[new TextEncoder().encode('Kom ihåg att du aldrig får snyta dig i mattan!')],
			);
			const presentedJwp = await presentSplitBbs(
				issuerJwk,
				issuedJwp,
				{ alg: 'experimental/SplitBBSv2.1', nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
				[0],
				deviceSign,
			);

			it("with a modified presentation header.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.slice(1)), "");
			});

			it("with a modified issuer header.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").map((s, i) => i === 1 ? s.slice(1) : s).join(".")), "");
			});

			it("without proof.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").slice(0, 3).join(".")), "");
			});

			it("with truncated proof.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.slice(0, presentedJwp.length - 4)), "");
			});

			it("with a disclosed payload omitted.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").map((s, i) => i === 2 ? '' : s).join(".")), "");
			});

			it("with a modified payload.", async () => {
				await asyncAssertThrows(() => verify(PK, presentedJwp.split(".").map((s, i) => i === 2 ? toBase64Url(new TextEncoder().encode('foo')) : s).join(".")), "Expected JWP verification to fail with modified message");
			});
		});
	});
});
