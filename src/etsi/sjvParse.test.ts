import axios from "axios";
import { afterAll, assert, describe, it } from "vitest";
import { Context, /*HttpClient*/ } from "../interfaces";
import { defaultHttpClient } from "../defaultHttpClient";
import { SDJWTVCParser } from "../credential-parsers/SDJWTVCParser";
import { SDJWTVCVerifier } from "../credential-verifiers/SDJWTVCVerifier";
import { PublicKeyResolverEngine } from "../PublicKeyResolverEngine";
import { ETSISDJWTVCSchema } from "./ETSISDJWTVCSchema";
import { CredentialVerificationError } from "../error";
import fs from "node:fs";

const inputFileArg = process.argv.find(arg =>
	arg.startsWith("--inputFile=")
);

const inputPath = "src/etsi/";

const inputFileName =
	inputFileArg?.split("=")[1] ??
	"credential";

const inputFile = `${inputPath}${inputFileName}`;

if (!fs.existsSync(inputFile)) {
	throw new Error(
		`Input file not found: ${inputFile}`
	);
}

const input = fs.readFileSync(
	inputFile,
	'utf8'
);

const context: Context = {
	clockTolerance: 0,
	lang: 'en-US',
	subtle: crypto.subtle,
	trustedCertificates: [],
	disableCertificateTrustCheck: true
};

describe("The SDJWT", () => {

	const report = {
		verifiedAt: new Date().toISOString(),
		tests: [] as any[]
	};

	afterAll(() => {
		fs.writeFileSync(
			"output/reports/etsi_errors.json",
			JSON.stringify(report, null, 2)
		);
	});

	const pkResolverEngine = PublicKeyResolverEngine();

	it("should be parsed successfully", async () => {
		console.log(input);
		const parser = SDJWTVCParser({ httpClient: defaultHttpClient, context });
		const parsedCredential = await parser.parse({ rawCredential: input });

		report.tests.push({
			test: "parse",
			success: parsedCredential.success
		});

		assert(parsedCredential.success === true);
		assert(parsedCredential.value.signedClaims);
	});

	it("should be verified successfully", async () => {
		const result = await SDJWTVCVerifier({ context, pkResolverEngine, httpClient: axios })
			.verify({
				rawCredential: input,
				opts: {}
			});

		report.tests.push({
			test: "verify",
			success: result.success,
			error: !result.success ? result.error : undefined
		});

		if (!result.success) {
			console.log((result as any).error);
		}
		assert(result.success === true || result.error === CredentialVerificationError.CannotExtractHolderPublicKey);
	});

	it("should conform to ETSI specs", async () => {

		const parser = SDJWTVCParser({ httpClient: defaultHttpClient, context });
		const parsedCredential = await parser.parse({ rawCredential: input });
		assert(parsedCredential.success === true);
		const etsiParse = ETSISDJWTVCSchema.safeParse(
			parsedCredential.value.signedClaims
		);

		report.tests.push({
			test: "etsi",
			success: etsiParse.success,
			issues: etsiParse.success
				? []
				: etsiParse.error.issues
		});

		// if (!etsiParse.success) {
		//     console.error(etsiParse.error);

		//     fs.writeFileSync(
		//         "output/reports/etsi_errors.json",
		//         JSON.stringify(
		//             {
		//                 verifiedAt: new Date().toISOString(),
		//                 issues: etsiParse.error.issues
		//             }
		//         )
		//     )
		// }
		etsiParse.error?.issues
		assert(etsiParse.success === true);
	});

});
