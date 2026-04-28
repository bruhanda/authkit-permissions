import type { AuditReason } from './audit.js';
import type { InferActions, InferResources } from './inference.js';
import type { PolicySpec } from './policy.js';

/**
 * Inspectable outcome returned by `enforcer.explain` — designed for audit
 * logs and test assertions, not for hot paths.
 */
export interface Decision<
  P extends PolicySpec,
  R extends InferResources<P> = InferResources<P>,
  A extends InferActions<P, R> = InferActions<P, R>,
> {
  /** Final verdict — only `true` grants the action. */
  readonly allowed: boolean;
  /** Why we decided this way. Same union as `AuditEvent.reason`. */
  readonly reason: AuditReason;
  /** Resource the decision was for. */
  readonly resource: R;
  /** Action the decision was for. */
  readonly action: A;
  /** Role the matching rule was inherited from (if any). */
  readonly grantedBy?: string;
  /** Condition that drove the verdict (if applicable). */
  readonly conditionName?: string;
  /** Wall-clock duration of the decision in ms (when timing is enabled). */
  readonly durationMs?: number;
}

/** Alias for an audit / decision reason — convenient for code that branches on it. */
export type DenyReason = AuditReason;
