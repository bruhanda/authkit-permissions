/**
 * Stable, exhaustive set of error codes thrown by `@authkit/permissions`.
 *
 * Codes are grouped into three tiers:
 *
 *  1. **Policy compile-time errors** (`INVALID_POLICY`, `ROLE_CYCLE`,
 *     `UNKNOWN_*`): thrown from `definePolicy()` so configuration mistakes
 *     crash fast at boot.
 *  2. **Per-check tenant guards** (`TENANT_REQUIRED`, `TENANT_MISMATCH`):
 *     thrown from `enforcer.check` / `enforcer.enforce` only — tenant
 *     leakage is treated as a security incident, not a deny.
 *  3. **Decision-pipeline diagnostics** (`CONDITION_THREW`,
 *     `ASYNC_CONDITION_IN_SYNC_PATH`, `AUDIT_FAILED`, `FORBIDDEN`):
 *     surfaced via either thrown `PermissionError` or audit reason
 *     depending on the surface (see plan §5.2).
 */
export const ERROR_CODES = Object.freeze({
  INVALID_POLICY: 'INVALID_POLICY',
  ROLE_CYCLE: 'ROLE_CYCLE',
  UNKNOWN_ROLE: 'UNKNOWN_ROLE',
  UNKNOWN_RESOURCE: 'UNKNOWN_RESOURCE',
  UNKNOWN_ACTION: 'UNKNOWN_ACTION',
  UNKNOWN_CONDITION: 'UNKNOWN_CONDITION',
  TENANT_REQUIRED: 'TENANT_REQUIRED',
  TENANT_MISMATCH: 'TENANT_MISMATCH',
  CONDITION_THREW: 'CONDITION_THREW',
  ASYNC_CONDITION_IN_SYNC_PATH: 'ASYNC_CONDITION_IN_SYNC_PATH',
  AUDIT_FAILED: 'AUDIT_FAILED',
  FORBIDDEN: 'FORBIDDEN',
} as const);

/** Union of every legal `PermissionError.code` value. */
export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];
