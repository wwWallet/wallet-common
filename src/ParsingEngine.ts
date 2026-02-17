import { CredentialParsingError } from "./error";
import { CredentialParser, ParsingEngineI } from "./interfaces";

export function ParsingEngine(): ParsingEngineI {
	const parsers: CredentialParser[] = [];

	return {
		register(parser: CredentialParser) {
			parsers.push(parser);
		},

		async parse({ rawCredential, credentialIssuer }) {
			for (const parser of parsers) {
				try {
					const result = await parser.parse({ rawCredential, credentialIssuer });

					// Parser not supported this format, try next parser
					if (!result.success && result.error === CredentialParsingError.UnsupportedFormat) {
						continue;
					}

					// Otherwise return immediately
					return result;

				} catch {
					return { success: false, error: CredentialParsingError.UnknownError };
				}
			}

			// No parser handled it
			return { success: false, error: CredentialParsingError.UnsupportedFormat };
		}
	};
}
