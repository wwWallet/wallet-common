import fs from 'node:fs'
import Crypto from 'node:crypto'
import { exec } from 'child_process'
import { SignJWT } from 'jose'
import axios from 'axios'

function generateCertificate () {
	return new Promise(resolve => {
		exec('openssl ecparam -name prime256v1 -genkey -noout -out ./test/fixtures/cert.key', () => {
			exec('openssl req -new -x509 -key ./test/fixtures/cert.key -out ./test/fixtures/cert.pem -days 3650 -subj /CN=test/C=FR/ST=test/L=test/O=test', () => {
				return resolve('ok');
			});
		});
	});
}

const vctClaims =  {
	"urn:eu.europa.ec.eudi:pid:1": {
		"expiry_date": "2035-04-21",
		"birth_place": "US",
		"birth_date": "1990-10-15",
		"issuance_date": "2025-03-04",
		"document_number": "12313213",
		"nationality": ["US"],
		"email_address": "john@sample.com",
		"age_over_18": false,
		"mobile_phone_number": "+308388338382",
		"resident_address": "23, Random str. 34793 Apt 3 USA",
		"given_name_birth": "John",
		"given_name": "John",
		"family_name": "Doe",
		"issuing_authority": "PID:00001",
		"issuing_country": "GR",
		"sex": 1,
	},
	"urn:eudi:pid:1": {
		"family_name": "test",
		"given_name": "test",
		"birthdate": "1923-12-25",
		"place_of_birth": {
			"locality": "test",
			"region": "test",
			"country": "GR",
		},
		"nationalities": ["GR"],
		"personal_administrative_number": "test",
		"birth_given_name": "test",
		"sex": 0,
		"email": "test@test.test",
		"date_of_expiry": "1925-01-17",
		"issuing_authority": "test",
		"issuing_country": "GR",
	},
	"urn:eudi:ehic:1": {
		"personal_administrative_number": "test",
		"issuing_authority": {
			"id": "test",
			"name": "test",
		},
		"issuing_country": "GR",
		"date_of_expiry": "1925-01-17",
		"document_number": "test",
	},
	"urn:eudi:pda1:1": {
		"personal_administrative_number": "test",
		"employer": "test",
		"work_address": {
			"formatted": "",
			"street_address": "",
		},
		"legislation_country": "GR",
		"issuing_authority": {
			"id": "test",
			"name": "test",
		},
		"issuing_country": "GR",
		"date_of_expiry": "1925-01-17",
		"date_of_issuance": "1925-01-17",
		"document_number": "test",
	},
	"urn:eu.europa.ec.eudi:por:1": {
		"legal_person_identifier": "test",
	},
	"unknown": {
		"unknown": true,
	},
	"urn:wwwallet:test": {
		"someKey": "SomeValue"
	}
};

const vctRegistryUri = 'https://qa.wwwallet.org/public/registry/all.json'

export function sdJwtFixture (vct: string = 'urn:eu.europa.ec.eudi:pid:1', opts: {
	vctmInHeader?: boolean,
	vctUrl?: string
} = { vctmInHeader: false }) {
	const claims = vctClaims[vct];

	return new Promise(async resolve => {
		await generateCertificate();
		const certPem = fs.readFileSync('./test/fixtures/cert.pem').toString('utf8');
		const privateKeyPem = fs.readFileSync('./test/fixtures/cert.key').toString('utf8');

		const cert = Crypto.createPublicKey(certPem);
		const privateKey = Crypto.createPrivateKey(privateKeyPem);
		const x5c = [
			certPem
			.replace('-----BEGIN CERTIFICATE-----\n', '')
			.replace('\n-----END CERTIFICATE-----\n', '')
		];

		const header = {
			"typ": "vc+sd-jwt",
			"alg": "ES256",
			"x5c": x5c
		};
		const vctms = await axios.get(vctRegistryUri).then(({ data }) => data);
		const vctm = vctms.map(vctm => Buffer.from(JSON.stringify(vctm)).toString('base64url'));

		if (opts.vctmInHeader) {
			header["vctm"] = vctm
		}

		const disclosures = Object.keys(claims).map(key => {
			const salt = (Math.random() + 1).toString(36)
			const rawDisclosure = [salt, key, claims[key]]
			const disclosure = Buffer.from(JSON.stringify(rawDisclosure)).toString('base64url')

			const hash = Crypto.createHash('sha256')
			const _sd = hash.update(disclosure).digest('base64url')


			return { _sd, disclosure, rawDisclosure }
		});

		const hash = Crypto.createHash('sha256');
		const integrity = hash.update(JSON.stringify(vctm)).digest('hex');


		const body = {
			"cnf": {
				"jwk": cert.export({ format: 'jwk' })
			},
			"vct": opts.vctUrl || vct,
			"vct#integrity": `SHA256-${integrity}`,
			"jti": "urn:vid:95611a1e-73cf-4fa7-8a27-f14c8251a54e",
			"iat": 1741106975,
			"exp": 1772642975,
			"iss": "http://wallet-enterprise-issuer:8003",
			"sub": "XqrJ53-wjsBZ3ARisBruvdpFOjvtRXlLg3fQbnfb_mU",
			"_sd_alg": "sha-256",
			"_sd": disclosures.map(({ _sd }) => _sd)
		}


		const jwt = await new SignJWT(body)
		.setProtectedHeader(header)
		.sign(privateKey);
		const sdJwt = jwt + '~' + disclosures.map(({ disclosure }) => disclosure).join('~') + '~';

		return resolve({ sdJwt, privateKey, cert, certPem, vctm: vctms.find(({ vct: current }) => current == vct) });
	});
}
