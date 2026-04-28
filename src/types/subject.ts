/**
 * The actor performing an action.
 *
 * `tenantId` is optional in the type but **required at runtime under default
 * `strictTenant: true`**. Single-tenant apps set `strictTenant: false` once
 * at policy definition time and stop threading the tenant through every call.
 *
 * Cross-tenant access (super-admin) is gated by two independent flags:
 *   1. `PolicyOptions.allowCrossTenant: true` (default `false`)
 *   2. `subject.crossTenant === true`
 *
 * Both must be set. A leaked / mirrored user-controlled string can no longer
 * escalate privileges by reaching `subject.tenantId`.
 */
export interface Subject<TRole extends string = string> {
  /** Stable user identifier. Used by conditions and audit logs. */
  readonly id: string;

  /**
   * Tenant the subject is acting on behalf of. Required when
   * `strictTenant: true` (default). When omitted under
   * `strictTenant: false`, the tenant guard is bypassed entirely.
   */
  readonly tenantId?: string;

  /** Roles assigned to this subject *for this tenantId*. */
  readonly roles: readonly TRole[];

  /**
   * Opt-in cross-tenant flag. Setting `true` is a no-op unless the policy
   * was constructed with `PolicyOptions.allowCrossTenant: true`. Even
   * then, every cross-tenant call is recorded in audit with
   * `crossTenant: true` and the granting policy id.
   */
  readonly crossTenant?: true;

  /** Optional bag for ABAC conditions (department, region, plan, ...). */
  readonly attributes?: Readonly<Record<string, unknown>>;
}
