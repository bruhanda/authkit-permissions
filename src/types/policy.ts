import type { ConditionFn, DeclarativeCondition } from './condition.js';
import type { InferActions, InferResources, InferRoles } from './inference.js';

/**
 * Top-level shape of a policy literal passed to `definePolicy()`.
 */
export interface PolicyDefinition<
  TRole extends string = string,
  TResource extends string = string,
  TAction extends string = string,
> {
  readonly roles: Readonly<Record<TRole, RoleDefinition<TRole>>>;
  readonly resources: Readonly<Record<TResource, ResourceDefinition<TAction>>>;
  readonly rules: ReadonlyArray<RuleLike<TRole, TResource, TAction>>;
  readonly options?: PolicyOptions;
}

/**
 * Loose rule shape used when the literal type isn't known yet (e.g. the
 * `PolicyDefinition` constraint). The strict, distributive `Rule<P>` below
 * narrows `action` to the resource it belongs to and is what consumers
 * actually see when they pass a literal policy through `definePolicy`.
 */
export interface RuleLike<
  TRole extends string = string,
  TResource extends string = string,
  TAction extends string = string,
> {
  readonly role: TRole | readonly TRole[];
  readonly resource: TResource | readonly TResource[] | '*';
  readonly action: TAction | readonly TAction[] | '*';
  readonly effect?: 'allow' | 'deny';
  readonly condition?: ConditionFn | DeclarativeCondition;
  readonly fields?: readonly [string, ...string[]];
  readonly priority?: number;
  readonly description?: string;
}

export interface RoleDefinition<TRole extends string = string> {
  readonly description?: string;
  /** Roles this role inherits from. Order is irrelevant; cycles fail at build. */
  readonly extends?: readonly TRole[];
}

export interface ResourceDefinition<TAction extends string = string> {
  readonly description?: string;
  readonly actions: readonly TAction[];
}

/**
 * Policy-wide options.
 */
export interface PolicyOptions {
  /**
   * Conflict resolution.
   *   - `'deny'`  (default) — deny-overrides
   *   - `'allow'`           — allow-overrides
   */
  readonly precedence?: 'deny' | 'allow';

  /**
   * Default `true`. When `true`, `subject.tenantId` is required at runtime
   * and a missing/empty value yields `tenant_mismatch`. When `false`,
   * the tenant guard is bypassed entirely (single-tenant mode).
   */
  readonly strictTenant?: boolean;

  /**
   * Default `false`. Cross-tenant access (super-admin) requires this AND
   * `subject.crossTenant === true`. With this `false`, setting
   * `crossTenant` on a subject is a no-op.
   */
  readonly allowCrossTenant?: boolean;

  /**
   * Default `'log'`. Behaviour when an audit hook throws/rejects:
   *   - `'log'`   — swallow + `console.warn` once; decision unchanged.
   *   - `'throw'` — rethrow as `AuditError` (caller decides).
   *   - `'deny'`  — force the decision to `{ allowed: false, reason: 'condition_threw' }`.
   */
  readonly auditFailureMode?: 'log' | 'throw' | 'deny';

  /** Throw at definition time if rules reference unknown ids. Default `true`. */
  readonly strictReferences?: boolean;

  /** Stable identifier for the policy version, written into audit events. */
  readonly id?: string;
}

/**
 * Distributive `Rule<P>` so when `resource` is the literal `'post'`,
 * `action` is constrained to `InferActions<P, 'post'>`.
 */
export type Rule<P extends PolicyDefinition> =
  | { [R in InferResources<P>]: RuleFor<P, R> }[InferResources<P>]
  | WildcardRule<P>;

export type RuleFor<
  P extends PolicyDefinition,
  R extends InferResources<P>,
> = {
  readonly role: InferRoles<P> | readonly InferRoles<P>[];
  readonly resource: R | readonly R[];
  readonly action: InferActions<P, R> | readonly InferActions<P, R>[] | '*';
  readonly effect?: 'allow' | 'deny';
  readonly condition?: ConditionFn | DeclarativeCondition;
  readonly fields?: readonly [string, ...string[]];
  readonly priority?: number;
  readonly description?: string;
};

export type WildcardRule<P extends PolicyDefinition> = {
  readonly role: InferRoles<P> | readonly InferRoles<P>[];
  readonly resource: '*';
  readonly action: '*';
  readonly effect?: 'allow' | 'deny';
  readonly condition?: ConditionFn | DeclarativeCondition;
  readonly priority?: number;
  readonly description?: string;
};

/**
 * The internal, normalized representation of a rule after `definePolicy`.
 * Always-array shapes simplify the evaluator.
 */
export interface NormalizedRule {
  readonly roles: readonly string[];
  readonly resources: readonly string[] | '*';
  readonly actions: readonly string[] | '*';
  readonly effect: 'allow' | 'deny';
  readonly condition?: ConditionFn | DeclarativeCondition;
  readonly fields?: readonly [string, ...string[]];
  readonly priority: number;
  readonly description?: string;
  /** Insertion order — used as the deterministic tiebreaker. */
  readonly order: number;
}
