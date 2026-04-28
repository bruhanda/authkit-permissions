import { definePolicy } from '../core/policy.js';
import type {
  ConditionEntry,
  TaggedAsyncCondition,
  TaggedSyncCondition,
} from '../types/condition.js';
import type { Policy, PolicySpec, ResourceDef, RuleDef } from '../types/policy.js';
import type { ValidatePolicy } from '../types/validate.js';
import { type BuilderState, emptyState, snapshot } from './fluent.js';

/**
 * Fluent builder around `definePolicy()`.
 *
 * Trades inferred literal types for an imperative, append-only build
 * pipeline. Useful when the policy is assembled from multiple modules
 * (e.g. one per feature) but the type-inference benefits of the literal
 * form are not needed at the call site of `enforcer.check`.
 *
 * The returned policy is type-erased to `PolicySpec` — call `definePolicy`
 * directly when you want full type-narrowed actions/resources at every
 * `enforcer.check`.
 *
 * @example
 *   const policy = createPolicyBuilder()
 *     .role('admin', { extends: ['member'] })
 *     .role('member')
 *     .resource('post', ['read', 'update'])
 *     .permit('admin', 'post', ['*'])
 *     .permit('member', 'post', ['read'])
 *     .build();
 */
export function createPolicyBuilder(): PolicyBuilder {
  return new PolicyBuilder(emptyState());
}

export class PolicyBuilder {
  constructor(private readonly state: BuilderState) {}

  /** Tag the policy with a stable version string written into audit events. */
  version(value: string): this {
    this.state.version = value;
    return this;
  }

  /**
   * Declare a role and its inheritance chain.
   *
   * @param name - role name.
   * @param def - optional `extends` / `description` / `crossTenant`.
   */
  role(
    name: string,
    def: { readonly extends?: ReadonlyArray<string>; readonly description?: string; readonly crossTenant?: boolean } = {},
  ): this {
    this.state.roles[name] = def;
    return this;
  }

  /**
   * Declare a resource type and its closed action set.
   *
   * @param name - resource name.
   * @param actions - actions valid on this resource.
   * @param description - optional human-readable description.
   */
  resource(name: string, actions: ReadonlyArray<string>, description?: string): this {
    const def: { actions: ReadonlyArray<string>; description?: string } = { actions };
    if (description !== undefined) def.description = description;
    this.state.resources[name] = def as ResourceDef;
    return this;
  }

  /**
   * Register a tagged condition for use in rule `when` / `allOf` / `anyOf` / `not`.
   */
  condition(name: string, fn: TaggedSyncCondition | TaggedAsyncCondition): this {
    this.state.conditions[name] = fn as ConditionEntry;
    return this;
  }

  /**
   * Grant a role permission to perform actions on a resource.
   *
   * Accepts the same three shapes as the literal form: a `string[]` of
   * actions, a wildcard `['*']`, or an object form mapping each action to
   * a `RuleDef`.
   *
   * @param role - granting role.
   * @param resource - target resource.
   * @param permissions - permission shape (array, wildcard, or object).
   */
  permit(
    role: string,
    resource: string,
    permissions:
      | ReadonlyArray<string>
      | { readonly [action: string]: RuleDef | { readonly rule: RuleDef; readonly priority?: number } | undefined },
  ): this {
    const perRole = this.state.permissions[role] ?? (this.state.permissions[role] = {});
    perRole[resource] = permissions as never;
    return this;
  }

  /**
   * Finalise the builder and produce a frozen `Policy`.
   *
   * Runs the same structural validation as `definePolicy()`; type
   * inference is intentionally erased at this boundary.
   *
   * @returns a frozen `Policy<PolicySpec>` handle.
   */
  build(): Policy<PolicySpec> {
    const spec = snapshot(this.state) as PolicySpec & ValidatePolicy<PolicySpec>;
    return definePolicy(spec);
  }
}
