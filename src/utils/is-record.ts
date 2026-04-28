/**
 * Narrow `unknown` to a plain object keyed by strings.
 *
 * Excludes arrays and `null`. Useful when validating user-supplied policy
 * shapes and condition arguments without pulling in `zod`/`valibot`.
 *
 * @param value - candidate value.
 * @returns `true` if `value` is a non-null, non-array object.
 *
 * @example
 *   if (isRecord(input.permissions)) { for (const k of Object.keys(input.permissions)) ... }
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
