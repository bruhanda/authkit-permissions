/**
 * Stable, machine-readable error codes. Always present on every
 * `AuthkitPermissionsError` subclass — adapters convert them to HTTP
 * status codes.
 */
export type ErrorCode =
  | 'PERMISSION_DENIED'
  | 'TENANT_MISMATCH'
  | 'CROSS_TENANT_DISALLOWED'
  | 'INVALID_POLICY'
  | 'EMPTY_FIELDS'
  | 'CYCLE_DETECTED'
  | 'UNKNOWN_ROLE'
  | 'UNKNOWN_RESOURCE'
  | 'UNKNOWN_ACTION'
  | 'CONDITION_THREW'
  | 'AUDIT_FAILED';
