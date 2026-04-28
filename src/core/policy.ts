import { PermissionError } from '../errors/base.js';
import { ERROR_CODES } from '../errors/codes.js';
import { isRecord } from '../utils/is-record.js';
import type {
  Policy,
  PolicySpec,
  ResourcePermissions,
  RuleDef,
  RuleObject,
} from '../types/policy.js';
import type { ValidatePolicy } from '../types/validate.js';
import { collectConditionRefs } from './evaluator.js';
import { isRuleObject } from './effective.js';
import { deepFreeze } from './freeze.js';
import { buildRoleClosure } from './role-graph.js';

/**
 * Define a frozen, fully-typed RBAC/ABAC policy.
 *
 * The returned `Policy` is the source of truth for **all** compile-time
 * type inference (roles, resources, actions, conditions). It is also a
 * frozen runtime value — mutations throw in strict mode.
 *
 * Validation happens at definition time (fail-fast at boot):
 *
 *  - Role inheritance cycles (`ROLE_CYCLE`).
 *  - Self-extension and unknown role refs in `extends` (`UNKNOWN_ROLE`).
 *  - Unknown resource keys in `permissions` (`UNKNOWN_RESOURCE`).
 *  - Unknown action keys per resource (`UNKNOWN_ACTION`).
 *  - Unknown condition refs in rule `when` / `allOf` / `anyOf` / `not`
 *    (`UNKNOWN_CONDITION`).
 *  - Structural shape errors (`INVALID_POLICY`).
 *
 * @typeParam P - inferred shape of the literal. Never specify manually.
 * @param spec - declarative policy literal.
 * @returns frozen, validated `Policy<P>` handle.
 * @throws {@link PermissionError} on any of the structural conditions above.
 *
 * @example
 *   const policy = definePolicy({
 *     roles: { admin: { extends: ['member'] }, member: {} },
 *     resources: { post: { actions: ['read', 'update'] } },
 *     permissions: {
 *       admin:  { post: ['*'] },
 *       member: { post: ['read'] },
 *     },
 *   });
 */
export function definePolicy<const P extends PolicySpec>(
  spec: P & ValidatePolicy<P>,
): Policy<P> {
  validatePolicy(spec);
  // Force-build the role-graph closure so cycles / unknown extends throw now,
  // not at first check.
  buildRoleClosure(spec);

  const handle: Policy<P> = {
    spec,
    __brand: 'authkit/policy',
  };
  return deepFreeze(handle);
}

function validatePolicy(spec: PolicySpec): void {
  if (!isRecord(spec)) {
    throw new PermissionError(ERROR_CODES.INVALID_POLICY, 'Policy must be an object');
  }
  if (!isRecord(spec.roles)) {
    throw new PermissionError(ERROR_CODES.INVALID_POLICY, 'Policy.roles must be an object');
  }
  if (!isRecord(spec.resources)) {
    throw new PermissionError(ERROR_CODES.INVALID_POLICY, 'Policy.resources must be an object');
  }
  if (!isRecord(spec.permissions)) {
    throw new PermissionError(
      ERROR_CODES.INVALID_POLICY,
      'Policy.permissions must be an object',
    );
  }

  for (const [name, def] of Object.entries(spec.resources)) {
    if (!isRecord(def) || !Array.isArray(def.actions)) {
      throw new PermissionError(
        ERROR_CODES.INVALID_POLICY,
        `Resource "${name}" must have an "actions" array`,
        { resource: name },
      );
    }
  }

  if (spec.conditions !== undefined) {
    if (!isRecord(spec.conditions)) {
      throw new PermissionError(
        ERROR_CODES.INVALID_POLICY,
        'Policy.conditions must be an object',
      );
    }
    for (const [name, fn] of Object.entries(spec.conditions)) {
      if (typeof fn !== 'function') {
        throw new PermissionError(
          ERROR_CODES.INVALID_POLICY,
          `Condition "${name}" must be a function`,
          { conditionName: name },
        );
      }
    }
  }

  const knownConditions = new Set(
    spec.conditions !== undefined ? Object.keys(spec.conditions) : [],
  );

  for (const [role, perResource] of Object.entries(spec.permissions)) {
    if (perResource === undefined) continue;
    // `Object.hasOwn` (Node 16.9+) skips the prototype chain so policies
    // keyed on `'toString'` / `'__proto__'` cannot bypass the unknown-role
    // check via `'toString' in {}` returning `true`.
    if (!Object.hasOwn(spec.roles, role)) {
      throw new PermissionError(
        ERROR_CODES.UNKNOWN_ROLE,
        `Permissions reference unknown role "${role}"`,
        { role },
      );
    }
    if (!isRecord(perResource)) {
      throw new PermissionError(
        ERROR_CODES.INVALID_POLICY,
        `Permissions for role "${role}" must be an object`,
        { role },
      );
    }
    for (const [resource, perms] of Object.entries(perResource)) {
      if (perms === undefined) continue;
      const resourceDef = spec.resources[resource];
      if (resourceDef === undefined) {
        throw new PermissionError(
          ERROR_CODES.UNKNOWN_RESOURCE,
          `Unknown resource "${resource}" in permissions for role "${role}"`,
          { role, resource },
        );
      }
      validateResourcePermissions(role, resource, perms, resourceDef.actions, knownConditions);
    }
  }
}

function validateResourcePermissions(
  role: string,
  resource: string,
  perms: ResourcePermissions<ResourceDefAny, string>,
  declaredActions: ReadonlyArray<string>,
  knownConditions: ReadonlySet<string>,
): void {
  const allowedActions = new Set<string>([...declaredActions, '*']);

  if (Array.isArray(perms)) {
    for (const action of perms as ReadonlyArray<string>) {
      if (!allowedActions.has(action)) {
        throw new PermissionError(
          ERROR_CODES.UNKNOWN_ACTION,
          `Unknown action "${action}" on resource "${resource}" for role "${role}"`,
          { role, resource, action },
        );
      }
    }
    return;
  }

  if (!isRecord(perms)) {
    throw new PermissionError(
      ERROR_CODES.INVALID_POLICY,
      `Permissions for role "${role}" on "${resource}" must be an array or object`,
      { role, resource },
    );
  }

  for (const [action, value] of Object.entries(perms)) {
    if (value === undefined) continue;
    if (!allowedActions.has(action)) {
      throw new PermissionError(
        ERROR_CODES.UNKNOWN_ACTION,
        `Unknown action "${action}" on resource "${resource}" for role "${role}"`,
        { role, resource, action },
      );
    }
    const rule: RuleDef = isRuleObject(value)
      ? (value as RuleObject).rule
      : (value as RuleDef);
    for (const ref of collectConditionRefs(rule)) {
      if (!knownConditions.has(ref)) {
        throw new PermissionError(
          ERROR_CODES.UNKNOWN_CONDITION,
          `Rule for "${role}.${resource}.${action}" references unknown condition "${ref}"`,
          { role, resource, action, conditionName: ref },
        );
      }
    }
  }
}

type ResourceDefAny = { readonly actions: ReadonlyArray<string> };
