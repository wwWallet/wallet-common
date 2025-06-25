import { describe, it } from 'vitest';
import { OpenidCredentialIssuerMetadataSchema } from './OpenidCredentialIssuerMetadataSchema';
import assert from 'assert';

const metadata = {
	"issuer": "https://wallet.a-sit.at/m6",
	"credential_issuer": "https://wallet.a-sit.at/m6",
	"authorization_servers": [
		"https://wallet.a-sit.at/m6"
	],
	"credential_endpoint": "https://wallet.a-sit.at/m6/credential",
	"nonce_endpoint": "https://wallet.a-sit.at/m6/nonce",
	"credential_response_encryption": {
		"alg_values_supported": [
			"ECDH-ES"
		],
		"enc_values_supported": [
			"A256GCM"
		],
		"encryption_required": false
	},
	"batch_credential_issuance": {
		"batch_size": 1
	},
	"credential_configurations_supported": {
		"eu.europa.ec.eudi.pid.1": {
			"format": "mso_mdoc",
			"scope": "eu.europa.ec.eudi.pid.1",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"cose_key"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"doctype": "eu.europa.ec.eudi.pid.1",
			"claims": [
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"family_name"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"given_name"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"birth_date"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_12"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_13"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_14"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_16"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_18"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_21"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_25"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_60"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_62"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_65"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_68"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_in_years"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_birth_year"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"family_name_birth"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"given_name_birth"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"birth_place"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"birth_country"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"birth_state"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"birth_city"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_address"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_country"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_state"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_city"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_postal_code"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_street"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_house_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"gender"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"sex"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"nationality"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuance_date"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"expiry_date"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuing_authority"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"document_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"administrative_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuing_country"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuing_jurisdiction"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"personal_administrative_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"portrait"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"email_address"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"mobile_phone_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"trust_anchor"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"location_status"
					]
				}
			]
		},
		"EuPid2023#jwt_vc_json": {
			"format": "jwt_vc_json",
			"scope": "EuPid2023#jwt_vc_json",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"credential_definition": {
				"type": [
					"VerifiableCredential",
					"EuPid2023"
				],
				"credentialSubject": {
					"family_name": {

					},
					"given_name": {

					},
					"birth_date": {

					},
					"age_over_12": {

					},
					"age_over_13": {

					},
					"age_over_14": {

					},
					"age_over_16": {

					},
					"age_over_18": {

					},
					"age_over_21": {

					},
					"age_over_25": {

					},
					"age_over_60": {

					},
					"age_over_62": {

					},
					"age_over_65": {

					},
					"age_over_68": {

					},
					"age_in_years": {

					},
					"age_birth_year": {

					},
					"family_name_birth": {

					},
					"given_name_birth": {

					},
					"birth_place": {

					},
					"birth_country": {

					},
					"birth_state": {

					},
					"birth_city": {

					},
					"resident_address": {

					},
					"resident_country": {

					},
					"resident_state": {

					},
					"resident_city": {

					},
					"resident_postal_code": {

					},
					"resident_street": {

					},
					"resident_house_number": {

					},
					"gender": {

					},
					"sex": {

					},
					"nationality": {

					},
					"issuance_date": {

					},
					"expiry_date": {

					},
					"issuing_authority": {

					},
					"document_number": {

					},
					"administrative_number": {

					},
					"issuing_country": {

					},
					"issuing_jurisdiction": {

					},
					"personal_administrative_number": {

					},
					"portrait": {

					},
					"email_address": {

					},
					"mobile_phone_number": {

					},
					"trust_anchor": {

					},
					"location_status": {

					}
				}
			}
		},
		"urn:eu.europa.ec.eudi:pid:1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:pid:1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:pid:1",
			"claims": [
				{
					"path": [
						"family_name"
					]
				},
				{
					"path": [
						"given_name"
					]
				},
				{
					"path": [
						"birth_date"
					]
				},
				{
					"path": [
						"age_over_12"
					]
				},
				{
					"path": [
						"age_over_13"
					]
				},
				{
					"path": [
						"age_over_14"
					]
				},
				{
					"path": [
						"age_over_16"
					]
				},
				{
					"path": [
						"age_over_18"
					]
				},
				{
					"path": [
						"age_over_21"
					]
				},
				{
					"path": [
						"age_over_25"
					]
				},
				{
					"path": [
						"age_over_60"
					]
				},
				{
					"path": [
						"age_over_62"
					]
				},
				{
					"path": [
						"age_over_65"
					]
				},
				{
					"path": [
						"age_over_68"
					]
				},
				{
					"path": [
						"age_in_years"
					]
				},
				{
					"path": [
						"age_birth_year"
					]
				},
				{
					"path": [
						"family_name_birth"
					]
				},
				{
					"path": [
						"given_name_birth"
					]
				},
				{
					"path": [
						"birth_place"
					]
				},
				{
					"path": [
						"birth_country"
					]
				},
				{
					"path": [
						"birth_state"
					]
				},
				{
					"path": [
						"birth_city"
					]
				},
				{
					"path": [
						"resident_address"
					]
				},
				{
					"path": [
						"resident_country"
					]
				},
				{
					"path": [
						"resident_state"
					]
				},
				{
					"path": [
						"resident_city"
					]
				},
				{
					"path": [
						"resident_postal_code"
					]
				},
				{
					"path": [
						"resident_street"
					]
				},
				{
					"path": [
						"resident_house_number"
					]
				},
				{
					"path": [
						"gender"
					]
				},
				{
					"path": [
						"sex"
					]
				},
				{
					"path": [
						"nationality"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				},
				{
					"path": [
						"personal_administrative_number"
					]
				},
				{
					"path": [
						"portrait"
					]
				},
				{
					"path": [
						"email_address"
					]
				},
				{
					"path": [
						"mobile_phone_number"
					]
				},
				{
					"path": [
						"trust_anchor"
					]
				},
				{
					"path": [
						"location_status"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:pid:1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:pid:1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:pid:1",
			"claims": [
				{
					"path": [
						"family_name"
					]
				},
				{
					"path": [
						"given_name"
					]
				},
				{
					"path": [
						"birth_date"
					]
				},
				{
					"path": [
						"age_over_12"
					]
				},
				{
					"path": [
						"age_over_13"
					]
				},
				{
					"path": [
						"age_over_14"
					]
				},
				{
					"path": [
						"age_over_16"
					]
				},
				{
					"path": [
						"age_over_18"
					]
				},
				{
					"path": [
						"age_over_21"
					]
				},
				{
					"path": [
						"age_over_25"
					]
				},
				{
					"path": [
						"age_over_60"
					]
				},
				{
					"path": [
						"age_over_62"
					]
				},
				{
					"path": [
						"age_over_65"
					]
				},
				{
					"path": [
						"age_over_68"
					]
				},
				{
					"path": [
						"age_in_years"
					]
				},
				{
					"path": [
						"age_birth_year"
					]
				},
				{
					"path": [
						"family_name_birth"
					]
				},
				{
					"path": [
						"given_name_birth"
					]
				},
				{
					"path": [
						"birth_place"
					]
				},
				{
					"path": [
						"birth_country"
					]
				},
				{
					"path": [
						"birth_state"
					]
				},
				{
					"path": [
						"birth_city"
					]
				},
				{
					"path": [
						"resident_address"
					]
				},
				{
					"path": [
						"resident_country"
					]
				},
				{
					"path": [
						"resident_state"
					]
				},
				{
					"path": [
						"resident_city"
					]
				},
				{
					"path": [
						"resident_postal_code"
					]
				},
				{
					"path": [
						"resident_street"
					]
				},
				{
					"path": [
						"resident_house_number"
					]
				},
				{
					"path": [
						"gender"
					]
				},
				{
					"path": [
						"sex"
					]
				},
				{
					"path": [
						"nationality"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				},
				{
					"path": [
						"personal_administrative_number"
					]
				},
				{
					"path": [
						"portrait"
					]
				},
				{
					"path": [
						"email_address"
					]
				},
				{
					"path": [
						"mobile_phone_number"
					]
				},
				{
					"path": [
						"trust_anchor"
					]
				},
				{
					"path": [
						"location_status"
					]
				}
			]
		},
		"urn:eudi:pid:1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "urn:eudi:pid:1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eudi:pid:1",
			"claims": [
				{
					"path": [
						"family_name"
					]
				},
				{
					"path": [
						"given_name"
					]
				},
				{
					"path": [
						"birthdate"
					]
				},
				{
					"path": [
						"place_of_birth",
						"country"
					]
				},
				{
					"path": [
						"place_of_birth",
						"region"
					]
				},
				{
					"path": [
						"place_of_birth",
						"locality"
					]
				},
				{
					"path": [
						"nationalities"
					]
				},
				{
					"path": [
						"address",
						"formatted"
					]
				},
				{
					"path": [
						"address",
						"country"
					]
				},
				{
					"path": [
						"address",
						"region"
					]
				},
				{
					"path": [
						"address",
						"locality"
					]
				},
				{
					"path": [
						"address",
						"postal_code"
					]
				},
				{
					"path": [
						"address",
						"street_address"
					]
				},
				{
					"path": [
						"address",
						"house_number"
					]
				},
				{
					"path": [
						"birth_family_name"
					]
				},
				{
					"path": [
						"birth_given_name"
					]
				},
				{
					"path": [
						"email"
					]
				},
				{
					"path": [
						"phone_number"
					]
				},
				{
					"path": [
						"picture"
					]
				},
				{
					"path": [
						"date_of_expiry"
					]
				},
				{
					"path": [
						"date_of_issuance"
					]
				},
				{
					"path": [
						"personal_administrative_number"
					]
				},
				{
					"path": [
						"sex"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"12"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"14"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"16"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"18"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"21"
					]
				},
				{
					"path": [
						"age_in_years"
					]
				},
				{
					"path": [
						"age_birth_year"
					]
				},
				{
					"path": [
						"trust_anchor"
					]
				}
			]
		},
		"urn:eudi:pid:1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "urn:eudi:pid:1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eudi:pid:1",
			"claims": [
				{
					"path": [
						"family_name"
					]
				},
				{
					"path": [
						"given_name"
					]
				},
				{
					"path": [
						"birthdate"
					]
				},
				{
					"path": [
						"place_of_birth",
						"country"
					]
				},
				{
					"path": [
						"place_of_birth",
						"region"
					]
				},
				{
					"path": [
						"place_of_birth",
						"locality"
					]
				},
				{
					"path": [
						"nationalities"
					]
				},
				{
					"path": [
						"address",
						"formatted"
					]
				},
				{
					"path": [
						"address",
						"country"
					]
				},
				{
					"path": [
						"address",
						"region"
					]
				},
				{
					"path": [
						"address",
						"locality"
					]
				},
				{
					"path": [
						"address",
						"postal_code"
					]
				},
				{
					"path": [
						"address",
						"street_address"
					]
				},
				{
					"path": [
						"address",
						"house_number"
					]
				},
				{
					"path": [
						"birth_family_name"
					]
				},
				{
					"path": [
						"birth_given_name"
					]
				},
				{
					"path": [
						"email"
					]
				},
				{
					"path": [
						"phone_number"
					]
				},
				{
					"path": [
						"picture"
					]
				},
				{
					"path": [
						"date_of_expiry"
					]
				},
				{
					"path": [
						"date_of_issuance"
					]
				},
				{
					"path": [
						"personal_administrative_number"
					]
				},
				{
					"path": [
						"sex"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"12"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"14"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"16"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"18"
					]
				},
				{
					"path": [
						"age_equal_or_over",
						"21"
					]
				},
				{
					"path": [
						"age_in_years"
					]
				},
				{
					"path": [
						"age_birth_year"
					]
				},
				{
					"path": [
						"trust_anchor"
					]
				}
			]
		},
		"org.iso.18013.5.1": {
			"format": "mso_mdoc",
			"scope": "org.iso.18013.5.1",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"cose_key"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"doctype": "org.iso.18013.5.1.mDL",
			"claims": [
				{
					"path": [
						"org.iso.18013.5.1",
						"family_name"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"given_name"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"birth_date"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"issue_date"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"expiry_date"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"issuing_country"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"issuing_authority"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"document_number"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"portrait"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"driving_privileges"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"un_distinguishing_sign"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"administrative_number"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"sex"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"height"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"weight"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"eye_colour"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"hair_colour"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"birth_place"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"resident_address"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"portrait_capture_date"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_in_years"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_birth_year"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_12"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_13"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_14"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_16"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_18"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_21"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_25"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_60"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_62"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_65"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"age_over_68"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"issuing_jurisdiction"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"nationality"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"resident_city"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"resident_state"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"resident_postal_code"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"resident_country"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"family_name_national_character"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"given_name_national_character"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"signature_usual_mark"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"biometric_template_face"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"biometric_template_finger"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"biometric_template_signature_sign"
					]
				},
				{
					"path": [
						"org.iso.18013.5.1",
						"biometric_template_iris"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:por:1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:por:1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:por:1",
			"claims": [
				{
					"path": [
						"legal_person_identifier"
					]
				},
				{
					"path": [
						"legal_name"
					]
				},
				{
					"path": [
						"full_powers"
					]
				},
				{
					"path": [
						"eService"
					]
				},
				{
					"path": [
						"effective_from_date"
					]
				},
				{
					"path": [
						"effective_until_date"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:por:1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:por:1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:por:1",
			"claims": [
				{
					"path": [
						"legal_person_identifier"
					]
				},
				{
					"path": [
						"legal_name"
					]
				},
				{
					"path": [
						"full_powers"
					]
				},
				{
					"path": [
						"eService"
					]
				},
				{
					"path": [
						"effective_from_date"
					]
				},
				{
					"path": [
						"effective_until_date"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"eu.europa.ec.eudi.hiid.1": {
			"format": "mso_mdoc",
			"scope": "eu.europa.ec.eudi.hiid.1",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"cose_key"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"doctype": "eu.europa.ec.eudi.hiid.1",
			"claims": [
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"health_insurance_id"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"patient_id"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"tax_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"one_time_token"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"wallet_e_prescription_code"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"affiliation_country"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"issue_date"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"expiry_date"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"issuing_authority"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"document_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"administrative_number"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"issuing_country"
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.hiid.1",
						"issuing_jurisdiction"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:hiid:1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:hiid:1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:hiid:1",
			"claims": [
				{
					"path": [
						"health_insurance_id"
					]
				},
				{
					"path": [
						"patient_id"
					]
				},
				{
					"path": [
						"tax_number"
					]
				},
				{
					"path": [
						"one_time_token"
					]
				},
				{
					"path": [
						"wallet_e_prescription_code"
					]
				},
				{
					"path": [
						"affiliation_country"
					]
				},
				{
					"path": [
						"issue_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:hiid:1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:hiid:1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:hiid:1",
			"claims": [
				{
					"path": [
						"health_insurance_id"
					]
				},
				{
					"path": [
						"patient_id"
					]
				},
				{
					"path": [
						"tax_number"
					]
				},
				{
					"path": [
						"one_time_token"
					]
				},
				{
					"path": [
						"wallet_e_prescription_code"
					]
				},
				{
					"path": [
						"affiliation_country"
					]
				},
				{
					"path": [
						"issue_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"eu.europa.ec.eudi.cor.1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "eu.europa.ec.eudi.cor.1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "eu.europa.ec.eudi.cor.1",
			"claims": []
		},
		"eu.europa.ec.eudi.cor.1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "eu.europa.ec.eudi.cor.1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "eu.europa.ec.eudi.cor.1",
			"claims": []
		},
		"urn:eu.europa.ec.eudi:cr:1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:cr:1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:cr:1",
			"claims": [
				{
					"path": [
						"company_name"
					]
				},
				{
					"path": [
						"company_type"
					]
				},
				{
					"path": [
						"company_status"
					]
				},
				{
					"path": [
						"company_activity"
					]
				},
				{
					"path": [
						"registration_date"
					]
				},
				{
					"path": [
						"company_end_date"
					]
				},
				{
					"path": [
						"company_EUID"
					]
				},
				{
					"path": [
						"vat_number"
					]
				},
				{
					"path": [
						"company_contact_data"
					]
				},
				{
					"path": [
						"registered_address"
					]
				},
				{
					"path": [
						"postal_address"
					]
				},
				{
					"path": [
						"branch"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:cr:1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:cr:1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:cr:1",
			"claims": [
				{
					"path": [
						"company_name"
					]
				},
				{
					"path": [
						"company_type"
					]
				},
				{
					"path": [
						"company_status"
					]
				},
				{
					"path": [
						"company_activity"
					]
				},
				{
					"path": [
						"registration_date"
					]
				},
				{
					"path": [
						"company_end_date"
					]
				},
				{
					"path": [
						"company_EUID"
					]
				},
				{
					"path": [
						"vat_number"
					]
				},
				{
					"path": [
						"company_contact_data"
					]
				},
				{
					"path": [
						"registered_address"
					]
				},
				{
					"path": [
						"postal_address"
					]
				},
				{
					"path": [
						"branch"
					]
				}
			]
		},
		"Tax_Number#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "Tax_Number#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "Tax Number",
			"claims": [
				{
					"path": [
						"tax_number"
					]
				},
				{
					"path": [
						"affiliation_country"
					]
				},
				{
					"path": [
						"registered_family_name"
					]
				},
				{
					"path": [
						"registered_given_name"
					]
				},
				{
					"path": [
						"resident_address"
					]
				},
				{
					"path": [
						"birth_date"
					]
				},
				{
					"path": [
						"church_tax_ID"
					]
				},
				{
					"path": [
						"iban"
					]
				},
				{
					"path": [
						"pid_id"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"verification_status"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"Tax_Number#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "Tax_Number#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "Tax Number",
			"claims": [
				{
					"path": [
						"tax_number"
					]
				},
				{
					"path": [
						"affiliation_country"
					]
				},
				{
					"path": [
						"registered_family_name"
					]
				},
				{
					"path": [
						"registered_given_name"
					]
				},
				{
					"path": [
						"resident_address"
					]
				},
				{
					"path": [
						"birth_date"
					]
				},
				{
					"path": [
						"church_tax_ID"
					]
				},
				{
					"path": [
						"iban"
					]
				},
				{
					"path": [
						"pid_id"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"verification_status"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:tax:1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:tax:1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:tax:1",
			"claims": [
				{
					"path": [
						"tax_number"
					]
				},
				{
					"path": [
						"affiliation_country"
					]
				},
				{
					"path": [
						"registered_family_name"
					]
				},
				{
					"path": [
						"registered_given_name"
					]
				},
				{
					"path": [
						"resident_address"
					]
				},
				{
					"path": [
						"birth_date"
					]
				},
				{
					"path": [
						"church_tax_ID"
					]
				},
				{
					"path": [
						"iban"
					]
				},
				{
					"path": [
						"pid_id"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"verification_status"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"urn:eu.europa.ec.eudi:tax:1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "urn:eu.europa.ec.eudi:tax:1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eu.europa.ec.eudi:tax:1",
			"claims": [
				{
					"path": [
						"tax_number"
					]
				},
				{
					"path": [
						"affiliation_country"
					]
				},
				{
					"path": [
						"registered_family_name"
					]
				},
				{
					"path": [
						"registered_given_name"
					]
				},
				{
					"path": [
						"resident_address"
					]
				},
				{
					"path": [
						"birth_date"
					]
				},
				{
					"path": [
						"church_tax_ID"
					]
				},
				{
					"path": [
						"iban"
					]
				},
				{
					"path": [
						"pid_id"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"verification_status"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"administrative_number"
					]
				},
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"issuing_jurisdiction"
					]
				}
			]
		},
		"urn:eudi:ehic:1#vc+sd-jwt": {
			"format": "vc+sd-jwt",
			"scope": "urn:eudi:ehic:1#vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eudi:ehic:1",
			"claims": [
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"social_security_number"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				}
			]
		},
		"urn:eudi:ehic:1#dc+sd-jwt": {
			"format": "dc+sd-jwt",
			"scope": "urn:eudi:ehic:1#dc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"jwk",
				"urn:ietf:params:oauth:jwk-thumbprint"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"vct": "urn:eudi:ehic:1",
			"claims": [
				{
					"path": [
						"issuing_country"
					]
				},
				{
					"path": [
						"social_security_number"
					]
				},
				{
					"path": [
						"issuing_authority"
					]
				},
				{
					"path": [
						"document_number"
					]
				},
				{
					"path": [
						"issuance_date"
					]
				},
				{
					"path": [
						"expiry_date"
					]
				}
			]
		}
	}
};

describe("OpenidCredentialIssuerMetadataSchemaValera", () => {
	it("should successfully parse Valera issuer's metadata", async () => {
		const res = OpenidCredentialIssuerMetadataSchema.safeParse(metadata);
		if (res.error) {
			console.dir(res.error, { depth: null });
		}
		assert(res.success === true);
	})
})
