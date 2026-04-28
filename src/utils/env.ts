/**
 * Detect dev mode in a runtime-portable way.
 *
 * Cloudflare Workers and Deno do **not** declare `process` as a global at
 * all, so naive `process?.env?.NODE_ENV` references throw `ReferenceError`
 * — optional chaining only protects against `null`/`undefined`, not
 * undeclared identifiers. The only safe form is the `typeof` guard below.
 *
 * Direct `process.env` reads anywhere else in the package are banned (see
 * plan §9.3.1). All env probes go through this helper.
 *
 * @returns `true` when running outside production (or when `process` does
 *   not exist at all — Workers, Deno isolates).
 *
 * @example
 *   if (isDev()) console.warn('non-boolean condition result');
 */
export function isDev(): boolean {
  return (
    typeof process !== 'undefined' &&
    typeof process.env === 'object' &&
    process.env !== null &&
    process.env.NODE_ENV !== 'production'
  );
}
