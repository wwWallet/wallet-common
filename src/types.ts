import { CredentialParsingError } from "./error";

export enum VerifiableCredentialFormat {
	VC_SDJWT = "vc+sd-jwt",
	DC_SDJWT = "dc+sd-jwt",
	MSO_MDOC = "mso_mdoc",
}

export type CredentialIssuer = {
	id: string; // must have the value of "iss" attribute of an SD-JWT VC credential
	name: string;

	// ...other metadata
}

export type CredentialClaims = Record<string, unknown>;

export type Result<T, E> = { success: true; value: T } | { success: false; error: E };

export type ParserResult =
	| { success: true; value: ParsedCredential }
	| { success: false; error: CredentialParsingError | MetadataCode; message?: string };

export type CredentialPayload = {
	iss: string;
	vct: string;
	[key: string]: unknown;
};

export type MetadataCode =
	| "NOT_FOUND"
	| "HEADER_FAIL"
	| "INTEGRITY_MISSING"
	| "JWT_VC_ISSUER_MISMATCH"
	| "SCHEMA_FETCH_FAIL"
	| "SCHEMA_CONFLICT"
	| "INFINITE_RECURSION"
	| "PAYLOAD_FAIL"
	| "VCTM_DECODE_FAIL"
	| "UNKNOWN_ERROR"
	| "INTEGRITY_FAIL"
	| "SCHEMA_FAIL"
	| "JWT_VC_ISSUER_FAIL";

export type MetadataError = {
	error: MetadataCode;
	message?: string;
};

export type MetadataWarning = {
	code: MetadataCode;
	message?: string;
};

export type ParsedCredential = {
	metadata: {
		credential: {
			format: VerifiableCredentialFormat.VC_SDJWT | VerifiableCredentialFormat.DC_SDJWT,
			vct: string,
			name: string,
			metadataDocuments: Record<string, unknown>[],
			image: {
				dataUri: string,
			},
		} | {
			format: VerifiableCredentialFormat.MSO_MDOC,
			doctype: string,
			name: string,
			image: {
				dataUri: string,
			},
		},
		issuer: CredentialIssuer,
	},
	validityInfo: {
		validUntil?: Date,
		validFrom?: Date,
		signed?: Date,
	}
	signedClaims: CredentialClaims,
	warnings?: Array<MetadataWarning>;
};
