import { AuthkitPermissionsError } from './base.js';

export type PolicyErrorCode =
  | 'INVALID_POLICY'
  | 'EMPTY_FIELDS'
  | 'CYCLE_DETECTED'
  | 'UNKNOWN_ROLE'
  | 'UNKNOWN_RESOURCE'
  | 'UNKNOWN_ACTION';

/**
 * Thrown at `definePolicy()` time when the policy literal is malformed
 * (cycles, unknown references, empty field arrays, reserved sentinels).
 */
export class PolicyError extends AuthkitPermissionsError {
  public readonly code: PolicyErrorCode;
  public readonly path?: ReadonlyArray<string | number>;

  public constructor(
    code: PolicyErrorCode,
    message: string,
    options?: { path?: ReadonlyArray<string | number>; cause?: unknown },
  ) {
    super(message, options ? { cause: options.cause } : undefined);
    this.code = code;
    if (options?.path) this.path = options.path;
  }
}
