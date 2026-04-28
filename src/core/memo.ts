/**
 * Tiny size-bounded LRU keyed by string.
 *
 * `Map` preserves insertion order, so the first key in iteration order is
 * the least-recently-used. We delete-and-reinsert on hit to refresh.
 *
 * Used by the enforcer to memoise the per-role-set effective permission
 * table. The cache key is the sorted-joined role string itself — no hash
 * — because *any* hash collision in an authz cache can grant a subject
 * the permissions of a different role-set (plan §9.2.12).
 */
export class LRU<V> {
  private readonly map = new Map<string, V>();

  /**
   * @param capacity - upper bound on entries; minimum 1. Default 256.
   */
  constructor(private readonly capacity: number) {
    if (capacity < 1) {
      throw new RangeError('LRU capacity must be at least 1');
    }
  }

  /**
   * Look up `key`. Refreshes recency on hit.
   *
   * @returns the cached value, or `undefined` when the key is absent.
   */
  get(key: string): V | undefined {
    const v = this.map.get(key);
    if (v === undefined) return undefined;
    this.map.delete(key);
    this.map.set(key, v);
    return v;
  }

  /**
   * Insert (or refresh) `key`. Evicts the LRU entry when capacity is reached.
   */
  set(key: string, value: V): void {
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.capacity) {
      const first = this.map.keys().next().value;
      if (first !== undefined) this.map.delete(first);
    }
    this.map.set(key, value);
  }
}
