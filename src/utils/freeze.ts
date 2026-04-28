/**
 * Recursively `Object.freeze` an object, every nested object and every
 * array element. Mutating the input after `definePolicy()` returns becomes
 * a no-op (or a `TypeError` in strict mode).
 *
 * We deliberately walk objects and arrays only — `Date`, `Map`, `Set` and
 * other built-ins are not policy-shape values and are left alone.
 */
export function deepFreeze<T>(value: T): T {
  if (value === null || value === undefined) return value;
  if (typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;

  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
    return Object.freeze(value);
  }

  for (const key of Object.keys(value as object)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return Object.freeze(value);
}
