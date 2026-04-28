import type { AbilityCheckArgs } from '../types/check-args.js';
import type { Decision } from '../types/decision.js';
import type {
  DefaultInstances,
  InferActions,
  InferResources,
  InferRoles,
  ResourceInstanceMap,
} from '../types/inference.js';
import type { PolicyDefinition, NormalizedRule } from '../types/policy.js';
import type { Subject } from '../types/subject.js';
import { cacheFor, cacheKey } from '../utils/memoize.js';
import type { CompiledPolicy } from './evaluator.js';
import type { Permissions } from './permissions.js';

/**
 * Per-subject ability. Returned by `Permissions.abilityFor(subject)`.
 *
 * Same call shape as `Permissions` minus the `subject` argument — refactor-
 * safe and forwards-compatible.
 */
export interface Ability<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  readonly subject: Subject<InferRoles<TPolicy>>;

  /**
   * Sugar over `check(...).allowed`. Memoized per `(resource, action)` for
   * the lifetime of the bound subject — calls that include a `target` or
   * `context` skip the cache, since conditions can return different
   * verdicts for different inputs.
   *
   * @returns `true` when the action is allowed.
   */
  can<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: AbilityCheckArgs<TPolicy, R, A, TInstances>,
  ): boolean;

  /**
   * Sugar over `!check(...).allowed`.
   *
   * @returns `true` when the action is denied.
   */
  cannot<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: AbilityCheckArgs<TPolicy, R, A, TInstances>,
  ): boolean;

  /**
   * Returns a fully-described `Decision`.
   */
  check<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: AbilityCheckArgs<TPolicy, R, A, TInstances>,
  ): Decision;

  /**
   * Throws `PermissionError` if denied.
   *
   * @throws {PermissionError} When the decision is `allowed: false`.
   */
  enforce<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: AbilityCheckArgs<TPolicy, R, A, TInstances>,
  ): void;

  /**
   * Returns the array of fields the subject is allowed to read/write
   * for the given `(action, resource)`, or `'*'` for full access.
   *
   * Walks the same rule index used by `check()` and returns the union of
   * `fields` across every applicable allow rule.
   */
  fieldsFor<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: { resource: R; action: A },
  ): readonly string[] | '*';

  /** @internal — used by `accessibleBy()` to read the compiled policy. */
  readonly compiled: CompiledPolicy;
}

/**
 * Build a per-subject `Ability`. Internal — `Permissions.abilityFor()` is the
 * public factory.
 */
export function createAbility<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(
  permissions: Permissions<TPolicy, TInstances>,
  subject: Subject<InferRoles<TPolicy>>,
): Ability<TPolicy, TInstances> {
  const cache = cacheFor(subject);

  const checkInternal = (args: AbilityCheckArgs<TPolicy, never, never, TInstances>): Decision => {
    const cacheable = args.target === undefined && args.context === undefined;
    if (cacheable) {
      const key = cacheKey(args.resource as string, args.action as string);
      const cached = cache.get(key);
      if (cached) return cached;
      const decision = permissions.check({ ...args, subject } as never);
      cache.set(key, decision);
      return decision;
    }
    return permissions.check({ ...args, subject } as never);
  };

  const enforceInternal = (args: AbilityCheckArgs<TPolicy, never, never, TInstances>): void => {
    permissions.enforce({ ...args, subject } as never);
  };

  return {
    subject,
    can: (args) => checkInternal(args as never).allowed,
    cannot: (args) => !checkInternal(args as never).allowed,
    check: checkInternal as Ability<TPolicy, TInstances>['check'],
    enforce: enforceInternal as Ability<TPolicy, TInstances>['enforce'],
    fieldsFor: (args) =>
      computeFieldsFor(permissions, subject, args.resource as string, args.action as string),
    compiled: permissions.compiled,
  };
}

function computeFieldsFor<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy>,
>(
  permissions: Permissions<TPolicy, TInstances>,
  subject: Subject<InferRoles<TPolicy>>,
  resource: string,
  action: string,
): readonly string[] | '*' {
  const compiled = permissions.compiled;
  const effective = compiled.roleGraph.expand(subject.roles);
  const fields = new Set<string>();
  let hasUnconstrainedAllow = false;

  for (const rule of compiled.rules) {
    if (rule.effect !== 'allow') continue;
    if (!ruleMatches(rule, effective, resource, action)) continue;
    if (!rule.fields) {
      hasUnconstrainedAllow = true;
      continue;
    }
    for (const f of rule.fields) fields.add(f);
  }

  if (hasUnconstrainedAllow) return '*';
  return Array.from(fields);
}

function ruleMatches(
  rule: NormalizedRule,
  effectiveRoles: readonly string[],
  resource: string,
  action: string,
): boolean {
  const roleSet = new Set(rule.roles);
  let roleHit = false;
  for (const r of effectiveRoles) {
    if (roleSet.has(r)) {
      roleHit = true;
      break;
    }
  }
  if (!roleHit) return false;
  if (rule.resources !== '*' && !rule.resources.includes(resource)) return false;
  if (rule.actions !== '*' && !rule.actions.includes(action)) return false;
  return true;
}
