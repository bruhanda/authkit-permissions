import { compilePolicy } from '../core/define-policy.js';
import { createPermissions, type Permissions } from '../core/permissions.js';
import { invariant } from '../utils/invariant.js';
import type { ConditionFn, DeclarativeCondition } from '../types/condition.js';
import type {
  PolicyDefinition,
  PolicyOptions,
  RoleDefinition,
  ResourceDefinition,
  RuleLike,
} from '../types/policy.js';

/**
 * Imperative, fluent alternative to `definePolicy()`.
 *
 * Lives behind the `@authkit/permissions/builder` subpath so the 95 % of
 * callers using a literal `definePolicy()` policy do not pay for its
 * mutable internals. Behaviour is identical to a literal policy: same
 * compile-time validation, same evaluator, same audit story.
 *
 * @example
 * ```ts
 * import { AbilityBuilder } from '@authkit/permissions/builder';
 *
 * const permissions = new AbilityBuilder()
 *   .role('member', { extends: ['viewer'] })
 *   .role('viewer')
 *   .resource('post', ['read', 'create', 'update', 'delete'])
 *   .allow('viewer', 'post', 'read')
 *   .allow('member', 'post', ['create', 'update'])
 *   .deny('member', 'post', 'delete')
 *   .priority(10)
 *   .build();
 * ```
 */
export class AbilityBuilder<
  TRole extends string = string,
  TResource extends string = string,
  TAction extends string = string,
> {
  readonly #roles = new Map<TRole, RoleDefinition<TRole>>();
  readonly #resources = new Map<TResource, ResourceDefinition<TAction>>();
  readonly #rules: RuleLike<TRole, TResource, TAction>[] = [];
  #options: PolicyOptions = {};
  #lastRule: RuleLike<TRole, TResource, TAction> | null = null;

  /**
   * Declare a role. Calling this twice for the same role overwrites the
   * previous definition.
   *
   * @param name Role identifier.
   * @param opts Optional inheritance config.
   * @returns `this` for chaining.
   */
  public role(name: TRole, opts?: { extends?: readonly TRole[] }): this {
    invariant(name !== '', 'INVALID_POLICY', 'Role name must not be empty.');
    this.#roles.set(name, opts?.extends ? { extends: opts.extends } : {});
    return this;
  }

  /**
   * Declare a resource and the actions it supports.
   *
   * @param name Resource identifier.
   * @param actions Non-empty list of actions on this resource.
   * @returns `this` for chaining.
   */
  public resource(name: TResource, actions: readonly TAction[]): this {
    invariant(name !== '', 'INVALID_POLICY', 'Resource name must not be empty.');
    invariant(actions.length > 0, 'INVALID_POLICY', `Resource "${name}" must declare at least one action.`);
    this.#resources.set(name, { actions });
    return this;
  }

  /**
   * Add an `allow` rule. Subsequent `.when()`/`.priority()` chain calls
   * attach to this rule.
   *
   * @param role Role(s) the rule applies to.
   * @param resource Resource (or `'*'`) the rule applies to.
   * @param action Action(s) (or `'*'`) the rule grants.
   * @returns `this` for chaining.
   */
  public allow(
    role: TRole | readonly TRole[],
    resource: TResource | readonly TResource[] | '*',
    action: TAction | readonly TAction[] | '*',
  ): this {
    const rule: RuleLike<TRole, TResource, TAction> = { role, resource, action, effect: 'allow' };
    this.#rules.push(rule);
    this.#lastRule = rule;
    return this;
  }

  /**
   * Add a `deny` rule. Subsequent `.when()`/`.priority()` chain calls
   * attach to this rule.
   *
   * @param role Role(s) the rule applies to.
   * @param resource Resource (or `'*'`) the rule applies to.
   * @param action Action(s) (or `'*'`) the rule denies.
   * @returns `this` for chaining.
   */
  public deny(
    role: TRole | readonly TRole[],
    resource: TResource | readonly TResource[] | '*',
    action: TAction | readonly TAction[] | '*',
  ): this {
    const rule: RuleLike<TRole, TResource, TAction> = { role, resource, action, effect: 'deny' };
    this.#rules.push(rule);
    this.#lastRule = rule;
    return this;
  }

  /**
   * Attach a condition to the most recently added rule.
   *
   * @param condition Either a `ConditionFn` or a declarative `eq`/`inList`.
   * @returns `this` for chaining.
   * @throws {PolicyError} `INVALID_POLICY` if no rule has been added yet.
   */
  public when(condition: ConditionFn | DeclarativeCondition): this {
    invariant(this.#lastRule != null, 'INVALID_POLICY', 'when() called before any allow()/deny().');
    (this.#lastRule as { condition?: ConditionFn | DeclarativeCondition }).condition = condition;
    return this;
  }

  /**
   * Set the priority of the most recently added rule. Higher wins.
   *
   * @param value Priority value (default `0`).
   * @returns `this` for chaining.
   * @throws {PolicyError} `INVALID_POLICY` if no rule has been added yet.
   */
  public priority(value: number): this {
    invariant(this.#lastRule != null, 'INVALID_POLICY', 'priority() called before any allow()/deny().');
    (this.#lastRule as { priority?: number }).priority = value;
    return this;
  }

  /**
   * Restrict the most recently added rule to a non-empty whitelist of fields.
   *
   * @param fields Non-empty tuple of field names.
   * @returns `this` for chaining.
   * @throws {PolicyError} `EMPTY_FIELDS` if `fields` is empty;
   *                      `INVALID_POLICY` if no rule has been added yet.
   */
  public fields(fields: readonly [string, ...string[]]): this {
    invariant(this.#lastRule != null, 'INVALID_POLICY', 'fields() called before any allow()/deny().');
    invariant(fields.length > 0, 'EMPTY_FIELDS', 'fields() requires a non-empty list.');
    (this.#lastRule as { fields?: readonly [string, ...string[]] }).fields = fields;
    return this;
  }

  /**
   * Set policy-wide options (precedence, strictTenant, ...). Calling twice
   * merges left-to-right.
   *
   * @param options Partial `PolicyOptions`.
   * @returns `this` for chaining.
   */
  public options(options: PolicyOptions): this {
    this.#options = { ...this.#options, ...options };
    return this;
  }

  /**
   * Compile the configured rules into a `Permissions` instance.
   *
   * @returns A fully validated `Permissions` object — same as the one
   *          `definePolicy()` produces.
   * @throws {PolicyError} For the same reasons as `definePolicy()`.
   */
  public build(): Permissions<PolicyDefinition<TRole, TResource, TAction>> {
    const rolesObj = Object.fromEntries(this.#roles) as Record<TRole, RoleDefinition<TRole>>;
    const resourcesObj = Object.fromEntries(this.#resources) as Record<TResource, ResourceDefinition<TAction>>;
    const policy: PolicyDefinition<TRole, TResource, TAction> = {
      roles: rolesObj,
      resources: resourcesObj,
      rules: this.#rules,
      options: this.#options,
    };
    const compiled = compilePolicy(policy);
    return createPermissions(policy, compiled);
  }
}
