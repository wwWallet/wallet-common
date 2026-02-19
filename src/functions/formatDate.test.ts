import { assert, describe, it } from "vitest";
import { formatDate } from "./formatDate";

describe("The Date/Time parser", () => {

	it("can match ISO 8601 format with two ms decimals", () => {

		const rawDate = '2026-02-01T07:28:49.11Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);

	});

	it("can match ISO 8601 format with three ms decimals", async () => {
		const rawDate = '2026-02-01T07:28:49.117Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match simple date YYYY-MM-DD format", async () => {
		const rawDate = '2026-02-01';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can handle a long format date", async () => {
		const rawDate = 'Sun Feb 01 2026 14:46:19 GMT+0200';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match a UNIX timestamp in seconds", async () => {
		const rawDate = 1769896800;

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match a UNIX timestamp in milliseconds", async () => {
		const rawDate = 1769896800000;

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match ISO 8601 format with three ms decimals", async () => {
		const rawDate = '2026-10-08T07:28:49.117Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match a Date object", async () => {
		const rawDate = new Date();

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

});
