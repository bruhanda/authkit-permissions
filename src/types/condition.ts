import type { ResourceDataMap } from './context.js';
import type { Subject } from './subject.js';

/**
 * Resolve the resource-instance type for a given `resourceType` literal.
 *
 * Falls back to `Record<string, unknown> | undefined` when the consumer has
 * not augmented `ResourceDataMap`, so unaugmented codebases keep compiling
 * and augmented ones gain narrowing inside condition bodies.
 */
type ResourceArgFor<R extends string> = R extends keyof ResourceDataMap
  ? ResourceDataMap[R]
  : Record<string, unknown> | undefined;

/**
 * Arguments passed to a condition function.
 *
 * Conditions are pure boolean predicates that consider the subject, the
 * resource instance (when supplied), and the action. They never mutate
 * shared state and never perform I/O on the hot path (use a sync condition
 * with pre-loaded data, or an async one with cache).
 *
 * Parameterise over `R extends string` so a condition that targets a
 * specific resource ("document") sees `resource` narrowed via
 * `ResourceDataMap['document']` instead of the wide
 * `Record<string, unknown> | undefined` (plan §4.4). The default keeps
 * the wide shape for unspecialised conditions.
 */
export interface ConditionArgs<R extends string = string> {
  /** Caller. */
  readonly subject: Subject;
  /**
   * Resource instance, when supplied at the call site. May be `undefined`
   * for permission probes that don't have an instance to test against.
   * Narrowed via `ResourceDataMap` when `R` is a known resource literal.
   */
  readonly resource?: ResourceArgFor<R>;
  /** String literal of the resource type, narrowed via `ResourceDataMap`. */
  readonly resourceType: R;
  /** Action name from the policy. */
  readonly action: string;
  /** Effective tenant scope of the check (subject's tenant or override). */
  readonly tenantId?: string;
}

/** Tagged sync condition — runs on `enforcer.checkSync` fast-path. */
export interface TaggedSyncCondition<TArgs = ConditionArgs> {
  (args: TArgs): boolean;
  readonly __authkitMode: 'sync';
}

/** Tagged async condition — `checkSync` throws `ASYNC_CONDITION_IN_SYNC_PATH`. */
export interface TaggedAsyncCondition<TArgs = ConditionArgs> {
  (args: TArgs): Promise<boolean>;
  readonly __authkitMode: 'async';
}

/** Plain sync predicate signature (no tag). */
export type ConditionFn<TArgs = ConditionArgs> = (args: TArgs) => boolean;

/** Plain async predicate signature (no tag). */
export type AsyncConditionFn<TArgs = ConditionArgs> = (
  args: TArgs,
) => Promise<boolean>;

/**
 * Accepted condition entry shape inside a `PolicySpec`.
 *
 * Tagged sync / async functions get the matching dispatch path. **Untagged**
 * arrows are accepted for terse policy literals but treated as **async** at
 * runtime — the cost of a spurious async path is one Promise allocation,
 * while the cost of a spurious sync path is a silent-allow security bug.
 */
export type ConditionEntry =
  | TaggedSyncCondition
  | TaggedAsyncCondition
  | ((args: ConditionArgs) => boolean | Promise<boolean>);
