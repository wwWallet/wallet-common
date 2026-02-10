import { it, describe } from 'vitest';
import { generateHS512Key, importHS512Key } from './HS512';
import { jwtVerify, SignJWT } from 'jose';

const alg = "HS512";

describe("The HS512 module", () => {
	it("should generate/import/export shared secret key, sign a jwt and then verify it", async () => {
		const { secret, exportedKey } = await generateHS512Key();

		const jwt = await new SignJWT({ 'urn:example:claim': true })
			.setProtectedHeader({ alg })
			.setIssuedAt()
			.setIssuer('urn:example:issuer')
			.setAudience('urn:example:audience')
			.setExpirationTime('30s')
			.sign(secret);

		const importedSecret = await importHS512Key(exportedKey);
		// verify with exported to make sure that export and import operations are working
		await jwtVerify(jwt, importedSecret);
	})
})
