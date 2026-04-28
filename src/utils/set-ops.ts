/**
 * Stable union of two readonly arrays without mutating inputs.
 *
 * Preserves insertion order: elements from `a` first, then unique elements
 * from `b`. Used when merging effective-permission rule lists from
 * different roles in the role-graph closure.
 *
 * @example
 *   union(['admin', 'member'], ['member', 'viewer']) // ['admin', 'member', 'viewer']
 */
export function union<T>(a: ReadonlyArray<T>, b: ReadonlyArray<T>): T[] {
  const seen = new Set<T>(a);
  const out: T[] = [...a];
  for (const v of b) {
    if (!seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}

/**
 * Intersection of two readonly arrays preserving the order of `b`.
 *
 * @example
 *   intersect(['a', 'b', 'c'], ['c', 'b']) // ['c', 'b']
 */
export function intersect<T>(a: ReadonlyArray<T>, b: ReadonlyArray<T>): T[] {
  const set = new Set<T>(a);
  return b.filter((v) => set.has(v));
}
