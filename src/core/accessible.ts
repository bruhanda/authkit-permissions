import type { ConditionEntry } from '../types/condition.js';
import type { FilterAst } from '../types/filter.js';
import type { InferActions, InferResources, InferRoles } from '../types/inference.js';
import type { PolicySpec, RuleDef } from '../types/policy.js';
import type { Subject } from '../types/subject.js';
import { getConditionFilter } from './conditions.js';
import {
  type CompiledEntry,
  type EffectiveTable,
  buildEffectiveTable,
} from './effective.js';
import type { RoleClosure } from './role-graph.js';

/** Inputs to `accessibleBy()`. */
export interface AccessibleByArgs<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> {
  readonly subject: Subject<InferRoles<P>>;
  readonly resource: R;
  readonly action: A;
}

/**
 * Internal accessor — exported for the public `accessibleBy` defined on the
 * enforcer. Lives in core/ rather than as a method on Enforcer so that
 * consumers who only call `enforcer.check` don't pay the bytes.
 *
 * Combines every rule that grants `(resource, action)` for the subject's
 * roles into an OR; lowers conditions to filter ASTs via their attached
 * hint, defaulting to `opaque` when no hint exists.
 */
export function computeAccessibleFilter<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(
  spec: P,
  closure: RoleClosure,
  conditions: Record<string, ConditionEntry>,
  table: EffectiveTable | undefined,
  args: AccessibleByArgs<P, R, A>,
): FilterAst {
  const effective = table ?? buildEffectiveTable(spec, closure, args.subject.roles);
  const bucket = effective.get(args.resource);
  if (bucket === undefined) return { kind: 'false' };

  const candidates: CompiledEntry[] = [];
  const exact = bucket.get(args.action);
  if (exact !== undefined) candidates.push(...exact);
  const wild = bucket.get('*');
  if (wild !== undefined) candidates.push(...wild);

  if (candidates.length === 0) return { kind: 'false' };

  const branches: FilterAst[] = [];
  for (const entry of candidates) {
    branches.push(lowerRule(entry.rule, conditions, args.subject));
  }
  return simplifyOr(branches);
}

function lowerRule(
  rule: RuleDef,
  conditions: Record<string, ConditionEntry>,
  subject: Subject,
): FilterAst {
  if (rule === true) return { kind: 'true' };
  if (typeof rule === 'string') return lowerCondition(rule, conditions, subject);
  if ('when' in rule) return lowerCondition(rule.when, conditions, subject);
  if ('allOf' in rule) {
    return simplifyAnd(
      rule.allOf.map((p) =>
        typeof p === 'string' ? lowerCondition(p, conditions, subject) : lowerRule(p, conditions, subject),
      ),
    );
  }
  if ('anyOf' in rule) {
    return simplifyOr(
      rule.anyOf.map((p) =>
        typeof p === 'string' ? lowerCondition(p, conditions, subject) : lowerRule(p, conditions, subject),
      ),
    );
  }
  // `not`
  const inner =
    typeof rule.not === 'string'
      ? lowerCondition(rule.not, conditions, subject)
      : lowerRule(rule.not, conditions, subject);
  if (inner.kind === 'true') return { kind: 'false' };
  if (inner.kind === 'false') return { kind: 'true' };
  return { kind: 'not', node: inner };
}

function lowerCondition(
  name: string,
  conditions: Record<string, ConditionEntry>,
  subject: Subject,
): FilterAst {
  const fn = conditions[name];
  if (fn === undefined) return { kind: 'opaque', conditionName: name };
  const hint = getConditionFilter(fn);
  if (hint === undefined) return { kind: 'opaque', conditionName: name };
  return hint(subject);
}

function simplifyAnd(nodes: ReadonlyArray<FilterAst>): FilterAst {
  const out: FilterAst[] = [];
  for (const node of nodes) {
    if (node.kind === 'true') continue;
    if (node.kind === 'false') return { kind: 'false' };
    if (node.kind === 'and') out.push(...node.nodes);
    else out.push(node);
  }
  if (out.length === 0) return { kind: 'true' };
  if (out.length === 1) return out[0] as FilterAst;
  return { kind: 'and', nodes: out };
}

function simplifyOr(nodes: ReadonlyArray<FilterAst>): FilterAst {
  const out: FilterAst[] = [];
  for (const node of nodes) {
    if (node.kind === 'false') continue;
    if (node.kind === 'true') return { kind: 'true' };
    if (node.kind === 'or') out.push(...node.nodes);
    else out.push(node);
  }
  if (out.length === 0) return { kind: 'false' };
  if (out.length === 1) return out[0] as FilterAst;
  return { kind: 'or', nodes: out };
}
