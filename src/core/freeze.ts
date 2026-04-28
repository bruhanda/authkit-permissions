/**
 * Recursively freeze a value's own enumerable properties.
 *
 * Bails on already-frozen targets to keep the cost O(n) in fresh nodes
 * instead of O(n²) in policy size. Used at `definePolicy()` time so any
 * mutation of the returned `Policy.spec` throws in strict mode.
 *
 * @param value - any value; primitives pass through.
 * @returns the same reference, deeply frozen.
 *
 * @example
 *   const policy = deepFreeze({ roles: { admin: {} } });
 *   policy.roles.admin = {}; // TypeError in strict mode
 */
export function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;

  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
    return value;
  }
  for (const key of Object.keys(value as object)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return value;
}
