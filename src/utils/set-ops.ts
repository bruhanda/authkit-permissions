/**
 * Internal Set helpers. Kept tiny so they tree-shake when unused.
 */

/** Union of two iterables, returning a fresh `Set`. */
export const union = <T>(a: Iterable<T>, b: Iterable<T>): Set<T> => {
  const out = new Set<T>(a);
  for (const v of b) out.add(v);
  return out;
};

/** Intersection of two iterables, returning a fresh `Set`. */
export const intersection = <T>(a: Iterable<T>, b: Iterable<T>): Set<T> => {
  const setB = b instanceof Set ? b : new Set<T>(b);
  const out = new Set<T>();
  for (const v of a) {
    if (setB.has(v)) out.add(v);
  }
  return out;
};
