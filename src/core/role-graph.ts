import { PolicyError } from '../errors/policy-error.js';
import type { RoleDefinition } from '../types/policy.js';
import { warnOnce } from '../utils/env.js';

/**
 * Compiled role hierarchy used by the evaluator. Maps every declared role
 * to its full set of effective roles (itself plus every transitively
 * inherited role).
 */
export interface RoleGraph {
  /**
   * Resolve a list of roles a subject was assigned to the full closure of
   * effective roles. Unknown roles are silently dropped (with a one-time
   * dev warning).
   */
  expand(assigned: readonly string[]): readonly string[];

  /** All declared role names — used when rules reference an unknown role. */
  hasRole(role: string): boolean;
}

/**
 * Build a `RoleGraph` from the policy's `roles` map. Throws
 * `PolicyError('CYCLE_DETECTED')` on direct or indirect cycles.
 */
export function buildRoleGraph(
  roles: Readonly<Record<string, RoleDefinition>>,
): RoleGraph {
  const declared = new Set(Object.keys(roles));
  const closures = new Map<string, readonly string[]>();

  for (const role of declared) {
    closures.set(role, computeClosure(role, roles, declared, []));
  }

  return {
    hasRole: (role) => declared.has(role),
    expand: (assigned) => {
      const out = new Set<string>();
      for (const role of assigned) {
        if (out.has(role)) continue;
        const closure = closures.get(role);
        if (!closure) {
          warnOnce(
            `unknown-role:${role}`,
            `[@authkit/permissions] Unknown role "${role}" in subject.roles — silently dropped.`,
          );
          continue;
        }
        for (const r of closure) out.add(r);
      }
      return Array.from(out);
    },
  };
}

function computeClosure(
  role: string,
  roles: Readonly<Record<string, RoleDefinition>>,
  declared: Set<string>,
  path: readonly string[],
): readonly string[] {
  if (path.includes(role)) {
    throw new PolicyError(
      'CYCLE_DETECTED',
      `Role inheritance cycle detected: ${[...path, role].join(' -> ')}`,
      { path: ['roles', ...path, role] },
    );
  }

  const out = new Set<string>([role]);
  const def = roles[role];
  const parents = def?.extends ?? [];
  const nextPath = [...path, role];

  for (const parent of parents) {
    if (!declared.has(parent)) {
      throw new PolicyError(
        'UNKNOWN_ROLE',
        `Role "${role}" extends unknown role "${parent}".`,
        { path: ['roles', role, 'extends'] },
      );
    }
    const closure = computeClosure(parent, roles, declared, nextPath);
    for (const r of closure) out.add(r);
  }

  return Array.from(out);
}
