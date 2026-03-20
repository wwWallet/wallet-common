import { assert, describe, it } from "vitest";
import { MemoryStore } from "./MemoryStore";

describe("MemoryStore", () => {
	it("set + get basic behavior", async () => {
		const store = new MemoryStore<string, string>();
		await store.set("k1", "v1");

		const value = await store.get("k1");
		assert(value === "v1");
	});

	it("get for missing key returns undefined", async () => {
		const store = new MemoryStore<string, string>();

		const value = await store.get("missing");
		assert(value === undefined);
	});

	it("delete removes key", async () => {
		const store = new MemoryStore<string, string>();
		await store.set("k1", "v1");
		await store.delete("k1");

		const value = await store.get("k1");
		assert(value === undefined);
	});

	it("set on existing key updates value and keeps single entry", async () => {
		const store = new MemoryStore<string, string>();
		await store.set("k1", "v1");
		await store.set("k1", "v2");

		const value = await store.get("k1");
		const all = await store.getAll();

		assert(value === "v2");
		assert(all.length === 1);
		assert(all[0] === "v2");
	});

	it("capacity eviction removes oldest entry when no reads happen", async () => {
		const store = new MemoryStore<string, string>(2);
		await store.set("a", "va");
		await store.set("b", "vb");
		await store.set("c", "vc");

		assert((await store.get("a")) === undefined);
		assert((await store.get("b")) === "vb");
		assert((await store.get("c")) === "vc");
	});

	it("get refreshes recency and affects LRU eviction", async () => {
		const store = new MemoryStore<string, string>(2);
		await store.set("a", "va");
		await store.set("b", "vb");
		await store.get("a");
		await store.set("c", "vc");

		assert((await store.get("a")) === "va");
		assert((await store.get("b")) === undefined);
		assert((await store.get("c")) === "vc");
	});

	it("re-setting existing key refreshes recency and affects LRU eviction", async () => {
		const store = new MemoryStore<string, string>(2);
		await store.set("a", "va");
		await store.set("b", "vb");
		await store.set("a", "va2");
		await store.set("c", "vc");

		assert((await store.get("a")) === "va2");
		assert((await store.get("b")) === undefined);
		assert((await store.get("c")) === "vc");
	});

	it("getAll returns current values after updates, evictions, and deletes", async () => {
		const store = new MemoryStore<string, string>(3);
		await store.set("a", "va");
		await store.set("b", "vb");
		await store.set("c", "vc");
		await store.set("b", "vb2");
		await store.delete("c");
		await store.set("d", "vd");
		await store.set("e", "ve");

		const all = await store.getAll();

		assert(all.length === 3);
		assert(all.includes("vb2"));
		assert(all.includes("vd"));
		assert(all.includes("ve"));
	});
});
