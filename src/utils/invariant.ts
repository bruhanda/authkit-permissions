import { PermissionError } from '../errors/base.js';
import type { ErrorCode } from '../errors/codes.js';

/**
 * Throw {@link PermissionError} when `condition` is falsy.
 *
 * Use at policy-compile and check-time guard points where a violation
 * indicates a misconfiguration or security incident (e.g. missing
 * `tenantId` under `strictTenant: true`).
 *
 * @param condition - value asserted to be truthy.
 * @param code - one of `ERROR_CODES` to discriminate the failure.
 * @param message - English diagnostic for humans / structured logs.
 * @param context - optional structured context, attached to the error.
 * @throws {@link PermissionError} when the condition is falsy.
 *
 * @example
 *   invariant(subject.tenantId, 'TENANT_REQUIRED', 'tenantId missing in strictTenant mode');
 */
export function invariant(
  condition: unknown,
  code: ErrorCode,
  message: string,
  context?: Record<string, unknown>,
): asserts condition {
  if (!condition) {
    throw new PermissionError(code, message, context);
  }
}
