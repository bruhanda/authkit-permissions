import type { Decision } from '../types/decision.js';
import type { ResourceInstance } from '../types/instances.js';
import type { Subject } from '../types/subject.js';

/**
 * The payload passed to every `AuditHook` invocation.
 *
 * Every field except the boolean flags is a stable, machine-readable
 * snapshot of the check that just happened.
 */
export interface AuditEvent {
  readonly subject: Subject;
  readonly action: string;
  readonly resource: string;
  readonly target?: ResourceInstance;
  readonly tenantId?: string;
  /** Present only when the call crossed tenants AND the policy allowed it. */
  readonly crossTenant?: true;
  readonly decision: Decision;
  /** ISO 8601 timestamp captured at the moment of the decision. */
  readonly timestamp: string;
  /** Stable id of the policy version, when one was supplied via `PolicyOptions.id`. */
  readonly policyId?: string;
}

/**
 * Called once per `check()`/`checkAsync()` after a decision is made.
 *
 * Sync `check()` does not await the returned promise (fire-and-forget);
 * `checkAsync()` does await it. Behaviour when the hook throws is
 * governed by `PolicyOptions.auditFailureMode`.
 */
export type AuditHook = (event: AuditEvent) => void | Promise<void>;
