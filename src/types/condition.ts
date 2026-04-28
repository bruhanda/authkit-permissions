import type { Subject } from './subject.js';
import type { ResourceInstance } from './instances.js';

/**
 * A condition function evaluated as part of a permission rule.
 *
 * Returning `true` means the rule applies; returning `false` (or rejecting)
 * means the rule does not match and evaluation falls through to the next
 * candidate rule.
 */
export type ConditionFn<
  TSubject extends Subject = Subject,
  TTarget = ResourceInstance,
  TCtx extends Record<string, unknown> = Record<string, unknown>,
> = (
  args: ConditionArgs<TSubject, TTarget, TCtx>,
) => boolean | Promise<boolean>;

/**
 * Arguments passed to a `ConditionFn`. The `target` is typed per-resource
 * when the consumer supplies `TInstances` to `definePolicy`.
 */
export interface ConditionArgs<
  TSubject extends Subject = Subject,
  TTarget = ResourceInstance,
  TCtx extends Record<string, unknown> = Record<string, unknown>,
> {
  readonly subject: TSubject;
  readonly target?: TTarget;
  readonly context: Readonly<TCtx>;
  readonly tenantId?: string;
  /** Stable monotonic clock for deterministic time-based rules in tests. */
  readonly now: () => Date;
}

/**
 * A declarative condition shape. Recognised by `accessibleBy()` so it can
 * lower the predicate to a SQL/Mongo `where` instead of treating it as an
 * opaque function. Use the `eq` / `inList` helpers from `@authkit/permissions`
 * to build these — building one by hand is supported but verbose.
 */
export type DeclarativeCondition =
  | { readonly kind: 'declarative-eq'; readonly field: string; readonly value: unknown | ((s: Subject) => unknown) }
  | { readonly kind: 'declarative-in'; readonly field: string; readonly values: readonly unknown[] | ((s: Subject) => readonly unknown[]) };
