/**
 * The ONLY module allowed to read `process` / runtime globals. All other
 * source files import `isProduction()` / `isDev()` from here.
 *
 * Cloudflare Workers and Deno do not declare `process` at all — direct
 * `process.env.NODE_ENV` reads throw `ReferenceError`. The `typeof process`
 * guard is the only portable check.
 */
const hasProcess = (): boolean => typeof process !== 'undefined';

/**
 * Returns `true` when running in a NODE_ENV=production environment.
 * Edge runtimes that do not expose `process` are treated as production
 * (no dev warnings — keeps cold-start logs quiet).
 */
export const isProduction = (): boolean => {
  if (!hasProcess()) return true;
  const env = process.env;
  return env != null && env.NODE_ENV === 'production';
};

/**
 * Returns `true` when running in a non-production environment.
 * Used to gate dev-only `console.warn` paths.
 */
export const isDev = (): boolean => !isProduction();

const warnedKeys = new Set<string>();

/**
 * `console.warn` exactly once per process for a given `key`. Used by the
 * dev warnings on async-condition-in-sync-check, unknown roles, etc.
 */
export const warnOnce = (key: string, ...args: unknown[]): void => {
  if (!isDev()) return;
  if (warnedKeys.has(key)) return;
  warnedKeys.add(key);
  // eslint-disable-next-line no-console
  console.warn(...args);
};

/** Test-only — clears the once-warning cache. */
export const __resetWarnOnceForTests = (): void => {
  warnedKeys.clear();
};
