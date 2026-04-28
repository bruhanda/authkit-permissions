import type { InferActions, InferConditions, InferResources, InferRoles } from './inference.js';
import type { PolicySpec, RuleDef } from './policy.js';

/**
 * Compiled (resource, action) entry produced by the role-graph closure.
 *
 * Stored once per role hierarchy and reused on every check; `priority` and
 * `order` make rule ordering deterministic (plan §9.2.6).
 */
export interface CompiledRule<P extends PolicySpec> {
  readonly resource: InferResources<P>;
  readonly action: string;
  readonly rule: RuleDef<InferConditions<P>>;
  readonly priority: number;
  /** Insertion order in the policy literal — deterministic tiebreaker. */
  readonly order: number;
  /** Role that declared (or inherited) the rule. */
  readonly grantedBy: InferRoles<P>;
}

/**
 * Read-only view of effective permissions for a role-set.
 *
 * Returned by `enforcer.permissionsOf(roles)`. Keyed by resource → action
 * → ordered rule list (priority desc, declaration order asc).
 */
export type EffectivePermissions<P extends PolicySpec> = {
  readonly [R in InferResources<P>]?: {
    readonly [A in InferActions<P, R> | '*']?: ReadonlyArray<CompiledRule<P>>;
  };
};
