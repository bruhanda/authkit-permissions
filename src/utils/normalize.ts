/**
 * Coerce a value-or-array into an array. Used inside the evaluator so the
 * decision algorithm doesn't have to branch on shape.
 */
export const toArray = <T>(value: T | readonly T[]): readonly T[] =>
  Array.isArray(value) ? (value as readonly T[]) : [value as T];

/**
 * Deduplicate a string-readonly array preserving first occurrence. Used
 * for role/effect-roles lists where order is irrelevant but determinism
 * is welcome for snapshots.
 */
export const dedupe = <T>(values: readonly T[]): readonly T[] => {
  const seen = new Set<T>();
  const out: T[] = [];
  for (const v of values) {
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
};
