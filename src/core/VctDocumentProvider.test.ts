import { assert, describe, it } from "vitest";
import { createVctDocumentResolutionEngine, VctDocumentProvider, VctResolutionErrors } from "./VctDocumentProvider";
import { ok, err } from "./Result";

const validDoc = (vct: string) => ({ vct });
const invalidDoc = { vct: "" }; // fails TypeMetadata's nonempty() check

const providerReturning = (result: Awaited<ReturnType<VctDocumentProvider["getVctMetadataDocument"]>>): VctDocumentProvider => ({
	getVctMetadataDocument: async () => result,
});

describe("createVctDocumentResolutionEngine", () => {
	it("returns the document from a single provider when valid", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(ok(validDoc("urn:example:a"))),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(result.ok);
		assert(result.value.vct === "urn:example:a");
	});

	it("returns NotFound when the single provider has nothing", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(err(VctResolutionErrors.NotFound)),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(!result.ok);
		assert(result.error === VctResolutionErrors.NotFound);
	});

	it("returns InvalidSchema when the single provider's document fails validation", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(ok(invalidDoc as any)),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(!result.ok);
		assert(result.error === VctResolutionErrors.InvalidSchema);
	});

	it("prefers the first provider's valid document over a later one", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(ok(validDoc("urn:example:first"))),
			providerReturning(ok(validDoc("urn:example:second"))),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(result.ok);
		assert(result.value.vct === "urn:example:first");
	});

	it("falls through to a later provider when an earlier one returns NotFound", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(err(VctResolutionErrors.NotFound)),
			providerReturning(ok(validDoc("urn:example:second"))),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(result.ok);
		assert(result.value.vct === "urn:example:second");
	});

	it("falls through to a later provider when an earlier one's document is InvalidSchema", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(ok(invalidDoc as any)),
			providerReturning(ok(validDoc("urn:example:second"))),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(result.ok);
		assert(result.value.vct === "urn:example:second");
	});

	it("returns NotFound when every provider has nothing", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(err(VctResolutionErrors.NotFound)),
			providerReturning(err(VctResolutionErrors.NotFound)),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(!result.ok);
		assert(result.error === VctResolutionErrors.NotFound);
	});

	it("falls back to the highest-priority InvalidSchema error when no provider has a valid document", async () => {
		const engine = createVctDocumentResolutionEngine([
			providerReturning(ok(invalidDoc as any)),
			providerReturning(err(VctResolutionErrors.NotFound)),
		]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(!result.ok);
		assert(result.error === VctResolutionErrors.InvalidSchema);
	});

	it("returns NotFound when there are no providers", async () => {
		const engine = createVctDocumentResolutionEngine([]);

		const result = await engine.getVctMetadataDocument("urn:example:a");

		assert(!result.ok);
		assert(result.error === VctResolutionErrors.NotFound);
	});
});
