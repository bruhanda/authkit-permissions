import type { ConditionEntry } from './condition.js';

/**
 * Definition of a single role in the policy.
 *
 * Roles inherit permissions from `extends` via a transitive closure
 * compiled at `definePolicy()` time. Cycles, self-extension, and
 * unknown role references throw `INVALID_POLICY` / `ROLE_CYCLE` /
 * `UNKNOWN_ROLE` at definition time.
 */
export interface RoleDef<TRole extends string = string> {
  /** Roles this role inherits permissions from. */
  readonly extends?: ReadonlyArray<TRole>;
  /** Optional human-readable description for audit/UX. */
  readonly description?: string;
  /**
   * Allow checks across tenants. Default `false`. **Audit-flagged** when
   * `true`. By itself, `crossTenant: true` does NOT bypass the tenant
   * guard — every cross-tenant call site must additionally pass
   * `allowCrossTenant: true` (defence in depth, plan §9.2.4).
   */
  readonly crossTenant?: boolean;
}

/** Definition of a single resource type. */
export interface ResourceDef<TAction extends string = string> {
  /** Closed set of actions valid on this resource. */
  readonly actions: ReadonlyArray<TAction>;
  /** Optional description for audit-friendly serialisation. */
  readonly description?: string;
}

/**
 * Composable rule shape. Symmetrical so users never have to remember
 * which combinator is implicit:
 *
 *   - `true`             — unconditional allow
 *   - `{ when: TCond }`  — sugar for `{ allOf: [TCond] }`
 *   - `{ allOf: [...] }` — every condition / nested rule must pass
 *   - `{ anyOf: [...] }` — at least one must pass
 *   - `{ not: <Rule> }`  — boolean inverse of a nested rule
 *
 * Combinators nest, so `(owner OR admin) AND sameTenant` is just
 * `{ allOf: [{ anyOf: ['owner', 'admin'] }, 'sameTenant'] }`.
 */
export type RuleDef<TCond extends string = string> =
  | true
  | { readonly when: TCond }
  | { readonly allOf: ReadonlyArray<TCond | RuleDef<TCond>> }
  | { readonly anyOf: ReadonlyArray<TCond | RuleDef<TCond>> }
  | { readonly not: TCond | RuleDef<TCond> };

/**
 * Wrapper that attaches an explicit `priority` to a rule.
 *
 * Higher priority wins; equal priority resolves by declaration order in
 * the policy literal. Default priority is `0`. Making ordering explicit
 * is an explicit contract (plan §9.2.6) so refactors that re-order keys
 * do not silently change behaviour.
 */
export interface RuleObject<TCond extends string = string> {
  readonly rule: RuleDef<TCond>;
  readonly priority?: number;
}

/**
 * Permissions granted on a single resource by a single role. Three escalating
 * shapes:
 *
 *   - `string[]` — implicit unconditional allow per action
 *   - `['*']`     — wildcard, expands to every declared action
 *   - object form — explicit per-action `RuleDef` / `RuleObject`
 */
export type ResourcePermissions<
  R extends ResourceDef,
  TCond extends string,
> =
  | ReadonlyArray<R['actions'][number] | '*'>
  | ({ readonly [A in R['actions'][number]]?: RuleDef<TCond> | RuleObject<TCond> } & {
      readonly '*'?: RuleDef<TCond> | RuleObject<TCond>;
    });

/**
 * Top-level shape passed to `definePolicy`.
 *
 * Cross-references (`extends`, action keys, condition refs) are tightened
 * to literal unions by `ValidatePolicy<P>` at the `definePolicy` boundary
 * — see `types/validate.ts`.
 */
export interface PolicySpec {
  /** Stable identifier written into audit events. */
  readonly version?: string;
  readonly roles: { readonly [role: string]: RoleDef };
  readonly resources: { readonly [resource: string]: ResourceDef };
  readonly conditions?: { readonly [condition: string]: ConditionEntry };
  readonly permissions: {
    readonly [role: string]: {
      readonly [resource: string]: ResourcePermissions<ResourceDef, string> | undefined;
    } | undefined;
  };
}

/**
 * Frozen, validated policy handle returned by `definePolicy`.
 *
 * The branded `__brand` field makes `Policy<A>` structurally incompatible
 * with `Policy<B>`, so an enforcer wired to one policy can't be passed a
 * subject typed for another at compile time.
 */
export interface Policy<P extends PolicySpec> {
  readonly spec: P;
  readonly __brand: 'authkit/policy';
}
