import { GenericStore } from "./Store";

export class MemoryStore<TKey, TValue> implements GenericStore<TKey, TValue> {
	private map = new Map<TKey, TValue>();

	constructor(private maxEntries: number = 1000) {}

	async get(key: TKey): Promise<TValue | undefined> {
		const value = this.map.get(key);
		if (value === undefined) return undefined;

		// Mark as recently used: move to the end
		this.map.delete(key);
		this.map.set(key, value);

		return value;
	}

	async delete(key: TKey): Promise<void> {
		this.map.delete(key);
	}

	async set(key: TKey, value: TValue): Promise<void> {
		// If key already exists, delete so reinsertion moves it to the end
		if (this.map.has(key)) {
			this.map.delete(key);
		}

		this.map.set(key, value);

		// Evict least recently used if above capacity
		if (this.map.size > this.maxEntries) {
			const oldestKey = this.map.keys().next().value as TKey;
			this.map.delete(oldestKey);
		}
	}

	async getAll(): Promise<TValue[]> {
		return Array.from(this.map.values());
	}
}
