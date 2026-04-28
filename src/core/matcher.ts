/**
 * Pure matching helpers. The evaluator uses these to decide whether a
 * normalized rule applies to a `(role, resource, action)` triple.
 */

/**
 * Returns `true` when `value` is in `pool` or `pool === '*'`.
 *
 * Wildcards never match the empty string — single-letter sentinels can
 * leak into runtime through serialization mistakes, so an empty `value`
 * always returns `false`.
 */
export const matches = (value: string, pool: readonly string[] | '*'): boolean => {
  if (value === '') return false;
  if (pool === '*') return true;
  if (pool.length === 0) return false;
  for (const p of pool) {
    if (p === value) return true;
  }
  return false;
};

/**
 * Returns `true` if any of the values in `subjectValues` is present in `pool`.
 * Used to test whether any of the subject's effective roles matches the
 * `roles` array of a normalized rule.
 */
export const matchesAny = (
  subjectValues: Iterable<string>,
  pool: readonly string[],
): boolean => {
  if (pool.length === 0) return false;
  const set = new Set(pool);
  for (const v of subjectValues) {
    if (set.has(v)) return true;
  }
  return false;
};
