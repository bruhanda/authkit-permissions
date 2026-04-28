/**
 * Catch-all shape for a "resource instance" passed to `check()` or seen by a
 * `condition`. Consumers typically supply a tighter, per-resource shape via
 * `definePolicy<TPolicy, TInstances>` — see `ResourceInstanceMap`.
 */
export interface ResourceInstance {
  /** When present, enables built-in tenant-mismatch detection. */
  readonly tenantId?: string;
  readonly [k: string]: unknown;
}
