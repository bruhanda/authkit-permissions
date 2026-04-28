import { isRecord } from '../utils/is-record.js';
import type { PolicySpec, ResourcePermissions, RuleDef, RuleObject } from '../types/policy.js';
import type { RoleClosure } from './role-graph.js';

/** Compiled (resource, action) entry — internal runtime shape. */
export interface CompiledEntry {
  readonly resource: string;
  readonly action: string;
  readonly rule: RuleDef;
  readonly priority: number;
  readonly order: number;
  readonly grantedBy: string;
}

/**
 * Effective permission table: resource → action (or `'*'`) → ordered rules.
 *
 * Action lists are sorted by priority desc, declaration order asc — making
 * the resolution order an explicit contract rather than load-bearing
 * implicit state (plan §9.2.6).
 */
export type EffectiveTable = ReadonlyMap<
  string,
  ReadonlyMap<string, ReadonlyArray<CompiledEntry>>
>;

/**
 * Compile the role-set's transitive permissions into a flat lookup table.
 *
 * Visits every ancestor role from the closure (most-specific to most-
 * general), normalises each `ResourcePermissions` shape into compiled
 * entries, and sorts each action bucket deterministically.
 *
 * @param spec - source policy.
 * @param closure - role-graph closure produced at `definePolicy` time.
 * @param roles - role-set carried by the subject.
 * @returns frozen effective table.
 *
 * @example
 *   const table = buildEffectiveTable(spec, closure, ['member']);
 */
export function buildEffectiveTable(
  spec: PolicySpec,
  closure: RoleClosure,
  roles: ReadonlyArray<string>,
): EffectiveTable {
  const ancestors: string[] = [];
  const seen = new Set<string>();
  for (const role of roles) {
    const list = closure.ancestorsOf.get(role);
    if (list === undefined) continue;
    for (const parent of list) {
      if (!seen.has(parent)) {
        seen.add(parent);
        ancestors.push(parent);
      }
    }
  }

  const byResource = new Map<string, Map<string, CompiledEntry[]>>();
  let order = 0;

  for (const role of ancestors) {
    const perRole = spec.permissions[role];
    if (perRole === undefined) continue;
    for (const [resource, perms] of Object.entries(perRole)) {
      if (perms === undefined) continue;
      const expanded = expandResourcePermissions(perms);
      let actionMap = byResource.get(resource);
      if (actionMap === undefined) {
        actionMap = new Map();
        byResource.set(resource, actionMap);
      }
      for (const entry of expanded) {
        let bucket = actionMap.get(entry.action);
        if (bucket === undefined) {
          bucket = [];
          actionMap.set(entry.action, bucket);
        }
        bucket.push({
          resource,
          action: entry.action,
          rule: entry.rule,
          priority: entry.priority,
          order: order++,
          grantedBy: role,
        });
      }
    }
  }

  for (const actionMap of byResource.values()) {
    for (const bucket of actionMap.values()) {
      bucket.sort((a, b) => b.priority - a.priority || a.order - b.order);
    }
  }

  return byResource as unknown as EffectiveTable;
}

/**
 * Normalise a `ResourcePermissions` value to a flat list of
 * `{ action, rule, priority }` entries. Used by `buildEffectiveTable`
 * and validation; isolated so the runtime validator can re-use the
 * same shape detection.
 */
export function expandResourcePermissions(
  perms: ResourcePermissions<ResourceDefAny, string>,
): Array<{ action: string; rule: RuleDef; priority: number }> {
  if (Array.isArray(perms)) {
    const out: Array<{ action: string; rule: RuleDef; priority: number }> = [];
    const seen = new Set<string>();
    for (const a of perms as ReadonlyArray<string>) {
      if (seen.has(a)) continue;
      seen.add(a);
      if (a === '*') {
        return [{ action: '*', rule: true, priority: 0 }];
      }
      out.push({ action: a, rule: true, priority: 0 });
    }
    return out;
  }
  const out: Array<{ action: string; rule: RuleDef; priority: number }> = [];
  for (const [action, value] of Object.entries(perms)) {
    if (value === undefined) continue;
    if (isRuleObject(value)) {
      out.push({ action, rule: value.rule, priority: value.priority ?? 0 });
    } else {
      out.push({ action, rule: value as RuleDef, priority: 0 });
    }
  }
  return out;
}

/**
 * Discriminate `RuleObject` from `RuleDef` at runtime. A `RuleObject` is
 * the only shape that carries a `rule` property and lacks the rule
 * combinator keys.
 */
export function isRuleObject(value: unknown): value is RuleObject {
  if (!isRecord(value)) return false;
  if (!('rule' in value)) return false;
  return !('when' in value || 'allOf' in value || 'anyOf' in value || 'not' in value);
}

/** Helper alias used internally to satisfy the shape constraint. */
type ResourceDefAny = { readonly actions: ReadonlyArray<string> };
