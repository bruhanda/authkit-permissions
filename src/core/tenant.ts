import type { ResourceInstance } from '../types/instances.js';
import type { PolicyOptions } from '../types/policy.js';
import type { Subject } from '../types/subject.js';

export type TenantGuardOutcome =
  | { kind: 'pass'; crossTenant: boolean }
  | { kind: 'tenant_mismatch' }
  | { kind: 'cross_tenant_disallowed' };

/**
 * Run the tenant-guard for a single check.
 *
 * Rules:
 *   - With `strictTenant: false`, the guard is bypassed entirely.
 *   - `subject.crossTenant === true` requires `allowCrossTenant: true`. With
 *     both set, the guard is bypassed and the call is flagged for audit.
 *   - When `subject.tenantId` is missing/empty under `strictTenant: true`,
 *     the call fails with `tenant_mismatch`.
 *   - When `target?.tenantId` is present and differs from
 *     `subject.tenantId`, the call fails with `tenant_mismatch`.
 *   - When `target?.tenantId` is `undefined`, the resource is treated as
 *     non-tenant-scoped and the guard short-circuits to `pass`.
 */
export function evaluateTenantGuard(
  subject: Subject,
  target: ResourceInstance | undefined,
  options: PolicyOptions,
): TenantGuardOutcome {
  if (options.strictTenant === false) {
    return { kind: 'pass', crossTenant: false };
  }

  if (subject.crossTenant === true) {
    if (options.allowCrossTenant === true) {
      return { kind: 'pass', crossTenant: true };
    }
    return { kind: 'cross_tenant_disallowed' };
  }

  if (subject.tenantId == null || subject.tenantId === '') {
    return { kind: 'tenant_mismatch' };
  }

  if (target == null) {
    return { kind: 'pass', crossTenant: false };
  }

  const targetTenant = target.tenantId;
  if (targetTenant !== undefined && targetTenant !== subject.tenantId) {
    return { kind: 'tenant_mismatch' };
  }

  return { kind: 'pass', crossTenant: false };
}
