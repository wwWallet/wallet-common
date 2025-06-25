import { describe, it } from 'vitest';
import { OpenidCredentialIssuerMetadataSchema } from './OpenidCredentialIssuerMetadataSchema';
import assert from 'assert';

const metadata = {
	"credential_issuer": "https://demo-issuer.wwwallet.org",
	"credential_endpoint": "https://demo-issuer.wwwallet.org/openid4vci/credential",
	"display": [
		{
			"name": "wwWallet Issuer",
			"logo": {
				"uri": "https://demo-issuer.wwwallet.org/images/logo.png"
			},
			"locale": "en-US"
		}
	],
	"credential_configurations_supported": {
		"urn:eudi:pid:1": {
			"scope": "pid:sd_jwt_vc",
			"vct": "urn:eudi:pid:1",
			"display": [
				{
					"name": "PID SD-JWT VC",
					"description": "Person Identification Data",
					"background_image": {
						"uri": "https://demo-issuer.wwwallet.org/images/background-image.png"
					},
					"background_color": "#1b263b",
					"text_color": "#FFFFFF",
					"locale": "en-US"
				}
			],
			"format": "vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"ES256"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"proof_types_supported": {
				"jwt": {
					"proof_signing_alg_values_supported": [
						"ES256"
					]
				}
			}
		},
		"eu.europa.ec.eudi.pid.1": {
			"scope": "pid:mso_mdoc",
			"doctype": "eu.europa.ec.eudi.pid.1",
			"display": [
				{
					"name": "PID - MDOC",
					"description": "Person Identification Data",
					"background_image": {
						"uri": "https://demo-issuer.wwwallet.org/images/background-image.png"
					},
					"background_color": "#4CC3DD",
					"text_color": "#000000",
					"locale": "en-US"
				}
			],
			"format": "mso_mdoc",
			"cryptographic_binding_methods_supported": [
				"ES256"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"proof_types_supported": {
				"jwt": {
					"proof_signing_alg_values_supported": [
						"ES256"
					]
				}
			}
		},
		"urn:credential:diploma": {
			"scope": "diploma",
			"vct": "urn:credential:diploma",
			"format": "vc+sd-jwt",
			"display": [
				{
					"name": "Bachelor Diploma - SD-JWT VC",
					"background_image": {
						"uri": "https://demo-issuer.wwwallet.org/images/background-image.png"
					},
					"logo": {
						"uri": "https://demo-issuer.wwwallet.org/images/diploma-logo.png"
					},
					"background_color": "#b1d3ff",
					"text_color": "#ffffff",
					"locale": "en-US"
				}
			],
			"cryptographic_binding_methods_supported": [
				"ES256"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"proof_types_supported": {
				"jwt": {
					"proof_signing_alg_values_supported": [
						"ES256"
					]
				}
			}
		},
		"urn:credential:ehic": {
			"scope": "ehic",
			"vct": "urn:credential:ehic",
			"format": "vc+sd-jwt",
			"display": [
				{
					"name": "EHIC - SD-JWT VC",
					"description": "European Health Insurance Card",
					"background_image": {
						"uri": "https://demo-issuer.wwwallet.org/images/background-image.png"
					},
					"background_color": "#1b263b",
					"text_color": "#FFFFFF",
					"locale": "en-US"
				}
			],
			"cryptographic_binding_methods_supported": [
				"ES256"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"proof_types_supported": {
				"jwt": {
					"proof_signing_alg_values_supported": [
						"ES256"
					]
				}
			}
		},
		"urn:eu.europa.ec.eudi:por:1": {
			"scope": "por:sd_jwt_vc",
			"vct": "urn:eu.europa.ec.eudi:por:1",
			"display": [
				{
					"name": "POR - SD-JWT VC",
					"description": "Power of Representation",
					"background_image": {
						"uri": "https://demo-issuer.wwwallet.org/images/background-image.png"
					},
					"background_color": "#c3b25d",
					"text_color": "#363531",
					"locale": "en-US"
				}
			],
			"format": "vc+sd-jwt",
			"cryptographic_binding_methods_supported": [
				"ES256"
			],
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"proof_types_supported": {
				"jwt": {
					"proof_signing_alg_values_supported": [
						"ES256"
					]
				}
			}
		}
	},
	"mdoc_iacas_uri": "https://demo-issuer.wwwallet.org/mdoc-iacas",
	"signed_metadata": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDTGpDQ0FkV2dBd0lCQWdJVWRnRVNiVEc5bnhTWFZJbUZkRkhIQUhHSjlSNHdDZ1lJS29aSXpqMEVBd0l3SURFUk1BOEdBMVVFQXd3SWQzZFhZV3hzWlhReEN6QUpCZ05WQkFZVEFrZFNNQjRYRFRJMU1ETXlNREE0TlRJME4xb1hEVE0xTURNeE9EQTROVEkwTjFvd01ERWhNQjhHQTFVRUF3d1laR1Z0YnkxcGMzTjFaWEl1ZDNkM1lXeHNaWFF1YjNKbk1Rc3dDUVlEVlFRR0V3SkhVakJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCT3NlU20xY1VSWnJpbkdNMGFFZHNMM21ERzlvbTBtUTFFSmR0bG1VQkl5RWxvcTZsdVlqNkdvQnA5VnpacDYwcGpZWSt5dEpiV2tiQURJVXNteXFibitqZ2R3d2dka3dId1lEVlIwakJCZ3dGb0FVZkhqNGJ6eXZvNHVuSHlzR3QrcE5hMFhzQmFJd0NRWURWUjBUQkFJd0FEQUxCZ05WSFE4RUJBTUNCYUF3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIQXdFd2FnWURWUjBSQkdNd1lZSVlkMkZzYkdWMExXVnVkR1Z5Y0hKcGMyVXRhWE56ZFdWeWdoTnBjM04xWlhJdWQzZDNZV3hzWlhRdWIzSm5naGhrWlcxdkxXbHpjM1ZsY2k1M2QzZGhiR3hsZEM1dmNtZUNGbkZoTFdsemMzVmxjaTUzZDNkaGJHeGxkQzV2Y21jd0hRWURWUjBPQkJZRUZLYWZhODdEUWJyWFlZdUplN1lvQ29Kb0dLL0xNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQjRXM1NiMG5LYm5iOFk3YUlaNG5qSkc3bEdTbTF4V09XUU1yQ3dneDlONUFpQmxJYTRFQVdmOU5pNFVNZVdGU1dJMktPQzVwUnlPQUVCU0dhdzlTK1BUd0E9PSJdfQ.eyJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vZGVtby1pc3N1ZXIud3d3YWxsZXQub3JnIiwiY3JlZGVudGlhbF9lbmRwb2ludCI6Imh0dHBzOi8vZGVtby1pc3N1ZXIud3d3YWxsZXQub3JnL29wZW5pZDR2Y2kvY3JlZGVudGlhbCIsImRpc3BsYXkiOlt7Im5hbWUiOiJ3d1dhbGxldCBJc3N1ZXIiLCJsb2dvIjp7InVyaSI6Imh0dHBzOi8vZGVtby1pc3N1ZXIud3d3YWxsZXQub3JnL2ltYWdlcy9sb2dvLnBuZyJ9LCJsb2NhbGUiOiJlbi1VUyJ9XSwiY3JlZGVudGlhbF9jb25maWd1cmF0aW9uc19zdXBwb3J0ZWQiOnsidXJuOmV1ZGk6cGlkOjEiOnsic2NvcGUiOiJwaWQ6c2Rfand0X3ZjIiwidmN0IjoidXJuOmV1ZGk6cGlkOjEiLCJkaXNwbGF5IjpbeyJuYW1lIjoiUElEIFNELUpXVCBWQyIsImRlc2NyaXB0aW9uIjoiUGVyc29uIElkZW50aWZpY2F0aW9uIERhdGEiLCJiYWNrZ3JvdW5kX2ltYWdlIjp7InVyaSI6Imh0dHBzOi8vZGVtby1pc3N1ZXIud3d3YWxsZXQub3JnL2ltYWdlcy9iYWNrZ3JvdW5kLWltYWdlLnBuZyJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiIzFiMjYzYiIsInRleHRfY29sb3IiOiIjRkZGRkZGIiwibG9jYWxlIjoiZW4tVVMifV0sImZvcm1hdCI6InZjK3NkLWp3dCIsImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIjp7InNjb3BlIjoicGlkOm1zb19tZG9jIiwiZG9jdHlwZSI6ImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiZGlzcGxheSI6W3sibmFtZSI6IlBJRCAtIE1ET0MiLCJkZXNjcmlwdGlvbiI6IlBlcnNvbiBJZGVudGlmaWNhdGlvbiBEYXRhIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovL2RlbW8taXNzdWVyLnd3d2FsbGV0Lm9yZy9pbWFnZXMvYmFja2dyb3VuZC1pbWFnZS5wbmcifSwiYmFja2dyb3VuZF9jb2xvciI6IiM0Q0MzREQiLCJ0ZXh0X2NvbG9yIjoiIzAwMDAwMCIsImxvY2FsZSI6ImVuLVVTIn1dLCJmb3JtYXQiOiJtc29fbWRvYyIsImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sInVybjpjcmVkZW50aWFsOmRpcGxvbWEiOnsic2NvcGUiOiJkaXBsb21hIiwidmN0IjoidXJuOmNyZWRlbnRpYWw6ZGlwbG9tYSIsImZvcm1hdCI6InZjK3NkLWp3dCIsImRpc3BsYXkiOlt7Im5hbWUiOiJCYWNoZWxvciBEaXBsb21hIC0gU0QtSldUIFZDIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovL2RlbW8taXNzdWVyLnd3d2FsbGV0Lm9yZy9pbWFnZXMvYmFja2dyb3VuZC1pbWFnZS5wbmcifSwibG9nbyI6eyJ1cmkiOiJodHRwczovL2RlbW8taXNzdWVyLnd3d2FsbGV0Lm9yZy9pbWFnZXMvZGlwbG9tYS1sb2dvLnBuZyJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiI2IxZDNmZiIsInRleHRfY29sb3IiOiIjZmZmZmZmIiwibG9jYWxlIjoiZW4tVVMifV0sImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sInVybjpjcmVkZW50aWFsOmVoaWMiOnsic2NvcGUiOiJlaGljIiwidmN0IjoidXJuOmNyZWRlbnRpYWw6ZWhpYyIsImZvcm1hdCI6InZjK3NkLWp3dCIsImRpc3BsYXkiOlt7Im5hbWUiOiJFSElDIC0gU0QtSldUIFZDIiwiZGVzY3JpcHRpb24iOiJFdXJvcGVhbiBIZWFsdGggSW5zdXJhbmNlIENhcmQiLCJiYWNrZ3JvdW5kX2ltYWdlIjp7InVyaSI6Imh0dHBzOi8vZGVtby1pc3N1ZXIud3d3YWxsZXQub3JnL2ltYWdlcy9iYWNrZ3JvdW5kLWltYWdlLnBuZyJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiIzFiMjYzYiIsInRleHRfY29sb3IiOiIjRkZGRkZGIiwibG9jYWxlIjoiZW4tVVMifV0sImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sInVybjpldS5ldXJvcGEuZWMuZXVkaTpwb3I6MSI6eyJzY29wZSI6InBvcjpzZF9qd3RfdmMiLCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cG9yOjEiLCJkaXNwbGF5IjpbeyJuYW1lIjoiUE9SIC0gU0QtSldUIFZDIiwiZGVzY3JpcHRpb24iOiJQb3dlciBvZiBSZXByZXNlbnRhdGlvbiIsImJhY2tncm91bmRfaW1hZ2UiOnsidXJpIjoiaHR0cHM6Ly9kZW1vLWlzc3Vlci53d3dhbGxldC5vcmcvaW1hZ2VzL2JhY2tncm91bmQtaW1hZ2UucG5nIn0sImJhY2tncm91bmRfY29sb3IiOiIjYzNiMjVkIiwidGV4dF9jb2xvciI6IiMzNjM1MzEiLCJsb2NhbGUiOiJlbi1VUyJ9XSwiZm9ybWF0IjoidmMrc2Qtand0IiwiY3J5cHRvZ3JhcGhpY19iaW5kaW5nX21ldGhvZHNfc3VwcG9ydGVkIjpbIkVTMjU2Il0sImNyZWRlbnRpYWxfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJwcm9vZl90eXBlc19zdXBwb3J0ZWQiOnsiand0Ijp7InByb29mX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXX19fX0sIm1kb2NfaWFjYXNfdXJpIjoiaHR0cHM6Ly9kZW1vLWlzc3Vlci53d3dhbGxldC5vcmcvbWRvYy1pYWNhcyIsImlhdCI6MTc0NTk0MTQ5MCwiaXNzIjoiaHR0cHM6Ly9kZW1vLWlzc3Vlci53d3dhbGxldC5vcmciLCJzdWIiOiJodHRwczovL2RlbW8taXNzdWVyLnd3d2FsbGV0Lm9yZyJ9.KaDtfGZEbYJOWHCSUajAIK4f34uyh7oX4VnWbPTfkVD2bdHs9UuOo95ZIKnkmXZnJXhxHAfsbNq4o2BjqayMtA"
};

describe("OpenidCredentialIssuerMetadataSchema", () => {
	it("should successfully parse issuer's metadata", async () => {
		const res = OpenidCredentialIssuerMetadataSchema.safeParse(metadata);
		assert(res.success === true);
	})
})
