import { assert, describe, it } from "vitest";
import { formatCborDate, isCborDate } from "./cborDate";

describe("isCborDate", () => {

	it("can match a CBOR Date object", () => {
		const cborDate = {
			date: '01-01-2026'
		};

		assert(isCborDate(cborDate));
	});

	it("can match a CBOR Date object with additional fields", () => {
		const cborDate = {
			date: '01-01-2026',
			approximate_mask: 'XXXXXXXX'
		};

		assert(isCborDate(cborDate));
	});

	it("does not match an object that is not a CBOR date", () => {
		const randomObject = {
			foo: 'bar'
		};

		assert(!isCborDate(randomObject));
	});


	it("does not match a simple date string", () => {
		const dateString = "04-06-2026";

		assert(!isCborDate(dateString));
	});
});

describe("isCborDate", () => {

	it("can format a CBOR Date object", () => {
		const cborDate = {
			date: '01-01-2026'
		};

		const formattedDate = formatCborDate(cborDate);
		console.log(formattedDate);
		assert(formattedDate === '01/01/2026');
	});

	it("does not alter an invalid CBOR object", () => {
		const invalidCborDateObject = {
			invalid_date: '01-01-2026',
		};

		const formattedDate = formatCborDate(invalidCborDateObject as any);

		console.log(invalidCborDateObject);
		console.log(formattedDate);

		assert(JSON.stringify(invalidCborDateObject) === JSON.stringify(formattedDate));
	});

});
