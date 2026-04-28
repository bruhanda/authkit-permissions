import { PolicyError } from '../errors/policy-error.js';
import type { ConditionFn, DeclarativeCondition } from '../types/condition.js';
import type {
  DefaultInstances,
  ResourceInstanceMap,
} from '../types/inference.js';
import type {
  NormalizedRule,
  PolicyDefinition,
  PolicyOptions,
  RuleLike,
} from '../types/policy.js';
import { deepFreeze } from '../utils/freeze.js';
import { invariant } from '../utils/invariant.js';
import { dedupe, toArray } from '../utils/normalize.js';
import type { CompiledPolicy } from './evaluator.js';
import { buildRoleGraph, type RoleGraph } from './role-graph.js';
import { createPermissions } from './permissions.js';
import type { Permissions } from './permissions.js';

const RESERVED_NAMES = new Set(['*', '']);

/**
 * Define an immutable, type-inferable RBAC/ABAC policy.
 *
 * The returned `Permissions` object exposes type-safe `check`, `can`,
 * `enforce`, `abilityFor` and helpers. All actions/resources/roles
 * referenced anywhere in this library are inferred from the policy
 * literal you pass here — there is no string-typed escape hatch.
 *
 * @typeParam TPolicy The literal type of the policy. Pass the policy as
 *                    an object literal (the `const` modifier on the type
 *                    parameter preserves literal types) for full inference.
 * @typeParam TInstances Optional map of resource-key -> concrete TS shape
 *                    for tightly-typed `target` parameters in conditions
 *                    and `check()` calls. Defaults to `ResourceInstance`.
 *
 * @param policy The policy definition. Frozen with `Object.freeze`
 *               recursively at construction time — mutating the input
 *               object after `definePolicy()` returns is a no-op.
 *
 * @returns A `Permissions<TPolicy, TInstances>` instance. Cheap to create
 *          (single pass over rules), safe to keep as a module-level
 *          singleton.
 *
 * @throws {PolicyError} `INVALID_POLICY` if the shape is malformed,
 *                       `CYCLE_DETECTED` if `roles[*].extends` forms a
 *                       cycle, `UNKNOWN_ROLE`/`UNKNOWN_RESOURCE`/
 *                       `UNKNOWN_ACTION` if a rule references something
 *                       not declared, `EMPTY_FIELDS` if any rule has
 *                       `fields: []`.
 *
 * @example
 * ```ts
 * import { definePolicy } from '@authkit/permissions';
 *
 * type Instances = { post: Post; billing: BillingAccount };
 *
 * export const permissions = definePolicy<typeof policy, Instances>({
 *   roles: {
 *     owner:  { extends: ['admin']  },
 *     admin:  { extends: ['member'] },
 *     member: { extends: ['viewer'] },
 *     viewer: {},
 *   },
 *   resources: {
 *     post:    { actions: ['read', 'create', 'update', 'delete', 'publish'] },
 *     billing: { actions: ['read', 'manage'] },
 *   },
 *   rules: [
 *     { role: 'viewer', resource: 'post',    action: 'read' },
 *     { role: 'admin',  resource: 'post',    action: '*' },
 *     { role: 'owner',  resource: 'billing', action: 'manage' },
 *     {
 *       role: 'member', resource: 'post', action: ['update', 'delete'],
 *       condition: ({ subject, target }) => target?.authorId === subject.id,
 *     },
 *   ],
 *   options: { precedence: 'deny', strictTenant: true },
 * } as const);
 * ```
 */
export function definePolicy<
  const TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(policy: TPolicy): Permissions<TPolicy, TInstances> {
  const compiled = compilePolicy(policy);
  return createPermissions<TPolicy, TInstances>(policy, compiled);
}

/**
 * Internal: validate, normalize and freeze a `PolicyDefinition`.
 * Exposed within the package so the imperative `AbilityBuilder` can reuse
 * the exact same compilation pipeline.
 */
export function compilePolicy(policy: PolicyDefinition): CompiledPolicy {
  validatePolicyShape(policy);

  // Validate role graph (throws on cycles + unknown extends).
  const roleGraph = buildRoleGraph(policy.roles);

  const options: PolicyOptions = policy.options ?? {};
  const strictRefs = options.strictReferences !== false;

  const declaredResources = new Set(Object.keys(policy.resources));
  const declaredActionsByResource = new Map<string, Set<string>>();
  for (const [name, def] of Object.entries(policy.resources)) {
    invariant(
      !RESERVED_NAMES.has(name),
      'INVALID_POLICY',
      `Reserved name "${name}" cannot be used as a resource id.`,
      ['resources', name],
    );
    invariant(
      Array.isArray(def?.actions) && def.actions.length > 0,
      'INVALID_POLICY',
      `Resource "${name}" must declare a non-empty 'actions' array.`,
      ['resources', name, 'actions'],
    );
    for (const a of def.actions) {
      invariant(
        !RESERVED_NAMES.has(a),
        'INVALID_POLICY',
        `Reserved name "${a}" cannot be used as an action id.`,
        ['resources', name, 'actions'],
      );
    }
    declaredActionsByResource.set(name, new Set(def.actions));
  }

  const normalized: NormalizedRule[] = policy.rules.map((rule, idx) =>
    normalizeRule(rule, idx, roleGraph, declaredResources, declaredActionsByResource, strictRefs),
  );

  const compiled: CompiledPolicy = {
    rules: normalized,
    options,
    roleGraph,
    ...(options.id !== undefined ? { id: options.id } : {}),
  };

  // Freeze input to honour the immutability contract. We deliberately do
  // NOT freeze `compiled` because it carries a `RoleGraph` whose closure
  // table is internal state.
  deepFreeze(policy);
  return compiled;
}

function validatePolicyShape(policy: PolicyDefinition): void {
  invariant(policy != null && typeof policy === 'object', 'INVALID_POLICY', 'Policy must be an object.');
  invariant(policy.roles != null && typeof policy.roles === 'object', 'INVALID_POLICY', 'Policy.roles must be an object.', ['roles']);
  invariant(policy.resources != null && typeof policy.resources === 'object', 'INVALID_POLICY', 'Policy.resources must be an object.', ['resources']);
  invariant(Array.isArray(policy.rules), 'INVALID_POLICY', 'Policy.rules must be an array.', ['rules']);

  for (const name of Object.keys(policy.roles)) {
    invariant(
      !RESERVED_NAMES.has(name),
      'INVALID_POLICY',
      `Reserved name "${name}" cannot be used as a role id.`,
      ['roles', name],
    );
  }
}

function normalizeRule(
  rule: RuleLike,
  order: number,
  roleGraph: RoleGraph,
  declaredResources: Set<string>,
  declaredActionsByResource: Map<string, Set<string>>,
  strictRefs: boolean,
): NormalizedRule {
  invariant(rule != null && typeof rule === 'object', 'INVALID_POLICY', `Rule #${order} must be an object.`, ['rules', order]);

  const roles = dedupe(toArray(rule.role)) as readonly string[];
  invariant(roles.length > 0, 'INVALID_POLICY', `Rule #${order} must declare at least one role.`, ['rules', order, 'role']);
  for (const r of roles) {
    if (!roleGraph.hasRole(r) && strictRefs) {
      throw new PolicyError(
        'UNKNOWN_ROLE',
        `Rule #${order} references unknown role "${r}".`,
        { path: ['rules', order, 'role'] },
      );
    }
  }

  const resources = normalizeResources(rule.resource, order, declaredResources, strictRefs);
  const actions = normalizeActions(rule.action, order, resources, declaredActionsByResource, strictRefs);

  if (rule.fields !== undefined) {
    invariant(
      Array.isArray(rule.fields) && rule.fields.length > 0,
      'EMPTY_FIELDS',
      `Rule #${order} has an empty 'fields' array. Empty arrays are ambiguous; omit the field instead.`,
      ['rules', order, 'fields'],
    );
  }

  const out: { -readonly [K in keyof NormalizedRule]: NormalizedRule[K] } = {
    roles,
    resources,
    actions,
    effect: rule.effect ?? 'allow',
    priority: rule.priority ?? 0,
    order,
  };
  if (rule.condition !== undefined) {
    out.condition = rule.condition as ConditionFn | DeclarativeCondition;
  }
  if (rule.fields !== undefined) out.fields = rule.fields;
  if (rule.description !== undefined) out.description = rule.description;
  return out;
}

function normalizeResources(
  resource: RuleLike['resource'],
  order: number,
  declared: Set<string>,
  strictRefs: boolean,
): readonly string[] | '*' {
  if (resource === '*') return '*';
  const arr = dedupe(toArray(resource)) as readonly string[];
  invariant(arr.length > 0, 'INVALID_POLICY', `Rule #${order} must declare at least one resource.`, ['rules', order, 'resource']);
  for (const r of arr) {
    invariant(r !== '*', 'INVALID_POLICY', `Rule #${order}: cannot mix '*' with named resources.`, ['rules', order, 'resource']);
    if (!declared.has(r) && strictRefs) {
      throw new PolicyError(
        'UNKNOWN_RESOURCE',
        `Rule #${order} references unknown resource "${r}".`,
        { path: ['rules', order, 'resource'] },
      );
    }
  }
  return arr;
}

function normalizeActions(
  action: RuleLike['action'],
  order: number,
  resources: readonly string[] | '*',
  declaredByResource: Map<string, Set<string>>,
  strictRefs: boolean,
): readonly string[] | '*' {
  if (action === '*') return '*';
  const arr = dedupe(toArray(action)) as readonly string[];
  invariant(arr.length > 0, 'INVALID_POLICY', `Rule #${order} must declare at least one action.`, ['rules', order, 'action']);
  for (const a of arr) {
    invariant(a !== '*', 'INVALID_POLICY', `Rule #${order}: cannot mix '*' with named actions.`, ['rules', order, 'action']);
  }
  if (!strictRefs) return arr;
  if (resources === '*') {
    // Wildcard-resource rule with named actions: enforce that each action
    // exists on at least one declared resource.
    const known = new Set<string>();
    for (const set of declaredByResource.values()) {
      for (const a of set) known.add(a);
    }
    for (const a of arr) {
      if (!known.has(a)) {
        throw new PolicyError(
          'UNKNOWN_ACTION',
          `Rule #${order} references unknown action "${a}".`,
          { path: ['rules', order, 'action'] },
        );
      }
    }
    return arr;
  }
  for (const r of resources) {
    const declared = declaredByResource.get(r);
    if (!declared) continue;
    for (const a of arr) {
      if (!declared.has(a)) {
        throw new PolicyError(
          'UNKNOWN_ACTION',
          `Rule #${order} references unknown action "${a}" on resource "${r}".`,
          { path: ['rules', order, 'action'] },
        );
      }
    }
  }
  return arr;
}
