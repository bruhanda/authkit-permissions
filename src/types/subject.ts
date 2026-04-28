/**
 * The actor performing an action.
 *
 * `tenantId` is optional in the type but **required at runtime under default
 * `strictTenant: true`**. Single-tenant apps disable `strictTenant` once at
 * enforcer construction and stop threading the tenant through every call.
 *
 * Cross-tenant access (super-admin) is gated by **two independent flags**
 * (defence in depth — see plan §9.2.4):
 *
 *  1. The role declares `crossTenant: true` in the policy.
 *  2. The call site passes `allowCrossTenant: true` on `CheckArgs`.
 *
 * Either alone is insufficient.
 */
export interface Subject<TRole extends string = string> {
  /** Stable user identifier. Used by conditions and audit logs. */
  readonly id: string;

  /** Roles assigned to this subject for `tenantId`. */
  readonly roles: ReadonlyArray<TRole>;

  /**
   * Tenant the subject is acting on behalf of. Required at runtime when
   * `strictTenant: true` (default).
   */
  readonly tenantId?: string;

  /** Optional bag for ABAC conditions (department, region, plan, ...). */
  readonly attrs?: Readonly<Record<string, unknown>>;
}
