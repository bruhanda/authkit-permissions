import type { Subject } from './subject.js';

/** Decision outcome reported on every audit event. */
export type AuditDecision = 'allow' | 'deny';

/**
 * Reason classifier. Drives logs, alerts, and incident attribution.
 *
 * - `allowed_by_rule` — at least one rule granted the action and all
 *   referenced conditions returned `true`.
 * - `no_matching_rule` — no rule for the (role, resource, action) triple.
 * - `no_roles` — subject has zero roles.
 * - `unknown_role_on_subject` — subject carries a role not present in
 *   the policy (rolling deploys mid-policy-change). Always denies — never
 *   throws — so live traffic can survive policy churn.
 * - `tenant_required` — strict-tenant violation (paired with the thrown
 *   `PermissionError(TENANT_REQUIRED)` for caller short-circuit).
 * - `tenant_mismatch` — subject and resource tenants differ without the
 *   double opt-in described in plan §9.2.4.
 * - `cross_tenant_disallowed` — `allowCrossTenant: true` was supplied but
 *   the role does not have `crossTenant: true`.
 * - `condition_failed` — a condition returned `false`.
 * - `condition_threw` — a condition threw / rejected. Decision is
 *   fail-closed (deny) — error is **not** re-thrown.
 * - `non_boolean_condition_result` — a condition returned a non-`true`
 *   value (truthy strings, objects, missing return). Treated as deny.
 * - `audit_failed` — emitted under `auditFailureMode: 'deny'` when an
 *   audit hook itself throws.
 */
export type AuditReason =
  | 'allowed_by_rule'
  | 'no_matching_rule'
  | 'no_roles'
  | 'unknown_role_on_subject'
  | 'tenant_required'
  | 'tenant_mismatch'
  | 'cross_tenant_disallowed'
  | 'condition_failed'
  | 'condition_threw'
  | 'non_boolean_condition_result'
  | 'audit_failed';

/**
 * Structured audit event emitted by the enforcer for every check.
 *
 * The event is intentionally serialisable JSON — auditing pipelines can
 * push it to Datadog / Loki / S3 without further transformation.
 */
export interface AuditEvent {
  /** Wall-clock ms since epoch when the decision was reached. */
  readonly ts: number;
  /** Policy version copied from `PolicySpec.version`, when present. */
  readonly version?: string;
  /** Allow / deny verdict. */
  readonly decision: AuditDecision;
  /** Why we decided this way. */
  readonly reason: AuditReason;
  /** Caller. */
  readonly subject: Subject;
  /** Action attempted. */
  readonly action: string;
  /** Resource type. */
  readonly resource: string;
  /** Resource instance (when supplied). */
  readonly data?: Readonly<Record<string, unknown>>;
  /** Tenant scope of the check. */
  readonly tenantId?: string;
  /** True when the call took the cross-tenant escape hatch. */
  readonly crossTenant?: boolean;
  /** Condition that produced the decision (when applicable). */
  readonly conditionName?: string;
  /** Original error when `reason === 'condition_threw'`. */
  readonly cause?: unknown;
  /** Role under which the matching rule was declared. */
  readonly grantedBy?: string;
  /** Wall-clock duration of the decision in ms (when timing wrapper used). */
  readonly durationMs?: number;
}

/**
 * Audit hook signature. May be sync or async; async hooks have an
 * awaitable boundary at the always-async `check`/`enforce` API so they
 * never get dropped on Cloudflare Workers.
 */
export type AuditHook = (event: AuditEvent) => void | Promise<void>;
