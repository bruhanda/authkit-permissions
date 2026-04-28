import { PermissionError } from '../errors/base.js';
import { ERROR_CODES } from '../errors/codes.js';
import type { PolicySpec } from '../types/policy.js';

/**
 * Compiled role-hierarchy closure.
 *
 * For every declared role, `ancestorsOf` carries the full transitive set of
 * inherited roles **including the role itself**, in dependency order
 * (most-specific first, then progressively-more-general parents). The
 * order matters for deterministic rule resolution (plan §9.2.6).
 */
export interface RoleClosure {
  readonly ancestorsOf: ReadonlyMap<string, ReadonlyArray<string>>;
}

/**
 * Compile a role hierarchy and return its transitive closure.
 *
 * Detects role cycles, self-extension, and unknown role references in
 * `extends`. Runs a single DFS per role with grey/black colouring so the
 * cycle path can be reported in the diagnostic.
 *
 * @param spec - the policy spec being defined.
 * @returns frozen closure handle.
 * @throws {@link PermissionError} `ROLE_CYCLE` when a cycle is detected.
 * @throws {@link PermissionError} `UNKNOWN_ROLE` when `extends` references
 *   an undeclared role.
 *
 * @example
 *   const closure = buildRoleClosure(spec);
 *   const ancestors = closure.ancestorsOf.get('member'); // ['member', 'viewer']
 */
export function buildRoleClosure(spec: PolicySpec): RoleClosure {
  const roleNames = Object.keys(spec.roles);
  const known = new Set(roleNames);

  for (const role of roleNames) {
    const def = spec.roles[role];
    if (def?.extends === undefined) continue;
    for (const parent of def.extends) {
      if (parent === role) {
        throw new PermissionError(
          ERROR_CODES.ROLE_CYCLE,
          `Role "${role}" extends itself`,
          { role },
        );
      }
      if (!known.has(parent)) {
        throw new PermissionError(
          ERROR_CODES.UNKNOWN_ROLE,
          `Role "${role}" extends unknown role "${parent}"`,
          { role, parent },
        );
      }
    }
  }

  const ancestorsOf = new Map<string, ReadonlyArray<string>>();

  for (const start of roleNames) {
    const visited = new Set<string>();
    const stack = new Set<string>();
    const path: string[] = [];
    const order: string[] = [];

    const visit = (role: string): void => {
      if (visited.has(role)) return;
      if (stack.has(role)) {
        const at = path.indexOf(role);
        const trail = [...path.slice(at), role].join(' -> ');
        throw new PermissionError(
          ERROR_CODES.ROLE_CYCLE,
          `Role inheritance cycle detected: ${trail}`,
          { cycle: trail },
        );
      }
      stack.add(role);
      path.push(role);
      order.push(role);
      const parents = spec.roles[role]?.extends ?? [];
      for (const p of parents) visit(p);
      stack.delete(role);
      path.pop();
      visited.add(role);
    };

    visit(start);
    ancestorsOf.set(start, order);
  }

  return { ancestorsOf };
}
