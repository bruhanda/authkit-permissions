import { AuthkitPermissionsError } from './base.js';

/**
 * Thrown when an audit hook throws/rejects and the policy is configured
 * with `auditFailureMode: 'throw'`.
 *
 * The original error is preserved on `cause` and via the standard
 * `Error.cause` chain.
 */
export class AuditError extends AuthkitPermissionsError {
  public readonly code = 'AUDIT_FAILED' as const;
  public override readonly cause: unknown;

  public constructor(message: string, cause: unknown) {
    super(message, { cause });
    this.cause = cause;
  }
}
