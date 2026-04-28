import { PermissionError } from './permission-error.js';

/**
 * Specialized `PermissionError` thrown when the tenant guard trips.
 *
 * Same response shape as `PermissionError`; subclassing exists so callers
 * can `catch (err: TenantMismatchError)` and emit a security-flavoured
 * audit event without re-checking `err.code`.
 */
export class TenantMismatchError extends PermissionError {
  public override readonly code: 'TENANT_MISMATCH' | 'CROSS_TENANT_DISALLOWED';

  public constructor(args: ConstructorParameters<typeof PermissionError>[0]) {
    super(args);
    if (this.decision.reason === 'cross_tenant_disallowed') {
      this.code = 'CROSS_TENANT_DISALLOWED';
    } else {
      this.code = 'TENANT_MISMATCH';
    }
  }
}
