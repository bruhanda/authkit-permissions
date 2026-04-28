/**
 * Reason code attached to every `Decision`. Drives logs, error messages
 * and debugging output.
 */
export type DecisionReason =
  | 'allowed_by_rule'
  | 'denied_by_rule'
  | 'no_matching_rule'
  | 'condition_failed'
  | 'condition_threw'
  | 'tenant_mismatch'
  | 'cross_tenant_disallowed'
  | 'subject_has_no_roles';

/**
 * The matched rule snapshot (a copy, never the live normalized rule).
 */
export interface MatchedRule {
  readonly role: string;
  readonly resource: string;
  readonly action: string;
  readonly effect: 'allow' | 'deny';
  readonly priority?: number;
  readonly description?: string;
}

/**
 * The verdict returned by `check()` / `checkAsync()` / `Ability.check()`.
 *
 * `Decision.allowed` is the only flag callers should consult to gate a
 * request. `reason`, `matchedRule`, `fields` and `warning` are observability
 * surface area.
 */
export interface Decision {
  /** Final verdict. `false` means: do not perform the action. */
  readonly allowed: boolean;

  /** Why we decided this way — drives logs, error messages, debugging. */
  readonly reason: DecisionReason;

  /** The single rule that produced the verdict, if any. */
  readonly matchedRule?: MatchedRule;

  /** Field whitelist, if the matched rule constrains attributes. Always non-empty if present. */
  readonly fields?: readonly string[];

  /** Wall-clock duration of the decision (ms). */
  readonly durationMs?: number;

  /** Non-fatal correctness signal (e.g. `'opaque_condition'`). */
  readonly warning?: 'opaque_condition' | 'async_condition_in_sync_check';
}
