import type { Subject } from './subject.js';

/**
 * Arguments passed to a condition function.
 *
 * Conditions are pure boolean predicates that consider the subject, the
 * resource instance (when supplied), and the action. They never mutate
 * shared state and never perform I/O on the hot path (use a sync condition
 * with pre-loaded data, or an async one with cache).
 */
export interface ConditionArgs<TData = Record<string, unknown> | undefined> {
  /** Caller. */
  readonly subject: Subject;
  /**
   * Resource instance, when supplied at the call site. May be `undefined`
   * for permission probes that don't have an instance to test against.
   */
  readonly resource?: TData;
  /** String literal of the resource type, narrowed via `ResourceDataMap`. */
  readonly resourceType: string;
  /** Action name from the policy, narrowed by the resource. */
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
