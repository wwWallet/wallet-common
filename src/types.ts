import { CredentialParsingError } from "./error";
import { ClaimMetadataEntry } from "./schemas/SdJwtVcTypeMetadataSchema";
import { JptClaims } from "./jpt";

export enum VerifiableCredentialFormat {
	VC_SDJWT = "vc+sd-jwt",
	DC_JPT = "dc+jpt",
	DC_SDJWT = "dc+sd-jwt",
	MSO_MDOC = "mso_mdoc",
}

export type CredentialIssuer = {
	id: string; // must have the value of "iss" attribute of an SD-JWT VC credential
	name: string;

	// ...other metadata
}

export type CredentialClaims = Record<string, unknown>;
export type CredentialJptClaims = JptClaims;

export type Result<T, E> = { success: true; value: T } | { success: false; error: E };

export type ParserResult =
	| { success: true; value: ParsedCredential }
	| { success: false; error: CredentialParsingError };

export type CredentialPayload = {
	iss: string;
	vct: string;
	[key: string]: unknown;
};

export type MetadataError = {
	error: CredentialParsingError;
};

export type MetadataWarning = {
	code: CredentialParsingError;
};

export type CredentialClaimPath = Array<string>;

export type CredentialFriendlyNameCallback = (
	preferredLangs?: string[]
) => Promise<string | null>;

export type ImageDataUriCallback = (
	filter?: Array<CredentialClaimPath>,
	preferredLangs?: string[]
) => Promise<string | null>;

export type TypeMetadata = {
	claims?: ClaimMetadataEntry[];
};

export type ParsedCredentialCommon = {
	metadata: {
		credential: unknown,
		issuer: CredentialIssuer,
	},
	validityInfo: {
		validUntil?: Date,
		validFrom?: Date,
		signed?: Date,
	},
	warnings?: Array<MetadataWarning>;
};

export type ParsedCredentialJwtOrMdoc = ParsedCredentialCommon & {
	metadata: {
		credential: {
			format: VerifiableCredentialFormat.VC_SDJWT | VerifiableCredentialFormat.DC_SDJWT,
			vct: string,
			name: CredentialFriendlyNameCallback,
			TypeMetadata: TypeMetadata,
			image: {
				dataUri: ImageDataUriCallback,
			},
		} | {
			format: VerifiableCredentialFormat.MSO_MDOC,
			doctype: string,
			name: CredentialFriendlyNameCallback,
			TypeMetadata: TypeMetadata,
			image: {
				dataUri: ImageDataUriCallback,
			},
		},
		issuer: CredentialIssuer,
	},
	signedClaims: CredentialClaims,
};

export type ParsedCredentialJpt = ParsedCredentialCommon & {
	metadata: {
		credential: {
			format: VerifiableCredentialFormat.DC_JPT,
			vct: string,
			name: CredentialFriendlyNameCallback,
			TypeMetadata: TypeMetadata,
			image: {
				dataUri: ImageDataUriCallback,
			},
		},
		issuer: CredentialIssuer,
	},
	issuerHeader: Record<string, unknown>,
	presentationHeader: Record<string, unknown> | null,
	signedJptClaims: CredentialJptClaims,
};

export type ParsedCredential = ParsedCredentialJwtOrMdoc | ParsedCredentialJpt;
