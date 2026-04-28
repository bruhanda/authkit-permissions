import type {
  ActionsByResource,
  DefaultInstances,
  InferActions,
  InferResources,
  InferRoles,
  ResourceInstanceMap,
} from './inference.js';
import type { PolicyDefinition } from './policy.js';
import type { Subject } from './subject.js';

/**
 * Argument shape for `Permissions.check`/`can`/`enforce`.
 *
 *   - `resource` is constrained to the policy's resource keys
 *   - `action`   is constrained to that resource's actions
 *   - `target`   is the resource instance, narrowed via `TInstances[R]`
 *   - `context`  is a free-form bag passed verbatim to conditions
 */
export interface CheckArgs<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  readonly subject: Subject<InferRoles<TPolicy>>;
  readonly resource: R;
  readonly action: A;
  /** The concrete resource instance, typed as `TInstances[R]` (e.g. `Post`). */
  readonly target?: TInstances[R];
  /** Free-form context bag passed verbatim to condition functions. */
  readonly context?: Readonly<Record<string, unknown>>;
}

/**
 * `Ability.check`/`can`/`enforce` argument shape — same as `CheckArgs`
 * minus `subject` (the ability is already bound to one).
 */
export type AbilityCheckArgs<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> = Omit<CheckArgs<TPolicy, R, A, TInstances>, 'subject'>;

/**
 * Convenience: union of every legal `(resource, action)` pair for a policy.
 * Used by `accessibleBy()` and the audit hook payload type.
 */
export type AnyResourceAction<TPolicy extends PolicyDefinition> = {
  [R in InferResources<TPolicy>]: { resource: R; action: ActionsByResource<TPolicy>[R] };
}[InferResources<TPolicy>];
