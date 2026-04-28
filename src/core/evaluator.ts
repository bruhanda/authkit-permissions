import type { Decision } from '../types/decision.js';
import type { ResourceInstance } from '../types/instances.js';
import type { NormalizedRule, PolicyOptions } from '../types/policy.js';
import type { Subject } from '../types/subject.js';
import { runConditionAsync, runConditionSync } from './condition.js';
import { makeDecision } from './decision.js';
import { matches, matchesAny } from './matcher.js';
import type { RoleGraph } from './role-graph.js';

/**
 * Compiled, query-friendly representation of a policy.
 *
 * The evaluator iterates `rules` in `(priority desc, order asc)` order,
 * stopping at the first applicable verdict. `roleGraph` is attached so
 * `Permissions` can expand a subject's assigned roles to the full closure
 * of inherited roles before matching.
 */
export interface CompiledPolicy {
  readonly rules: readonly NormalizedRule[];
  readonly options: Readonly<PolicyOptions>;
  readonly roleGraph: RoleGraph;
  /** Stable id of the policy version (for audit). */
  readonly id?: string;
}

/**
 * Args for a single decision pass — fully resolved (no inference) so the
 * evaluator stays small and cheap to test in isolation.
 */
export interface EvaluateArgs {
  readonly compiled: CompiledPolicy;
  readonly effectiveRoles: readonly string[];
  readonly resource: string;
  readonly action: string;
  readonly subject: Subject;
  readonly target: ResourceInstance | undefined;
  readonly context: Readonly<Record<string, unknown>>;
  readonly now: () => Date;
}

interface Candidate {
  readonly rule: NormalizedRule;
  readonly role: string;
}

/**
 * Synchronous decision pass. If a rule's condition returns a Promise the
 * evaluator surfaces `condition_failed` with `warning: 'async_condition_in_sync_check'`.
 */
export function evaluateSync(args: EvaluateArgs): Decision {
  const start = nowMs();

  const candidates = collectCandidates(args);
  if (candidates.length === 0) {
    return makeDecision(false, 'no_matching_rule', { durationMs: nowMs() - start });
  }

  const precedence = args.compiled.options.precedence ?? 'deny';
  let asyncWarning = false;
  let conditionThrew: { rule: NormalizedRule; role: string; cause: unknown } | undefined;

  for (const c of candidates) {
    const outcome = runConditionSync(c.rule.condition, {
      subject: args.subject,
      target: args.target,
      context: args.context,
      tenantId: args.subject.tenantId,
      now: args.now,
    });

    if (outcome.kind === 'matched') {
      const allowed = c.rule.effect === 'allow';
      if (allowed) {
        return makeDecision(true, 'allowed_by_rule', {
          rule: c.rule,
          matchedRole: c.role,
          matchedResource: args.resource,
          matchedAction: args.action,
          ...(c.rule.fields ? { fields: c.rule.fields } : {}),
          durationMs: nowMs() - start,
        });
      }
      if (precedence === 'deny') {
        return makeDecision(false, 'denied_by_rule', {
          rule: c.rule,
          matchedRole: c.role,
          matchedResource: args.resource,
          matchedAction: args.action,
          durationMs: nowMs() - start,
        });
      }
      // precedence === 'allow' — keep scanning for an explicit allow
      continue;
    }

    if (outcome.kind === 'threw') {
      conditionThrew ??= { rule: c.rule, role: c.role, cause: outcome.cause };
      continue;
    }

    if (outcome.kind === 'async_in_sync') {
      asyncWarning = true;
      continue;
    }
    // 'failed' — fall through to the next candidate.
  }

  if (conditionThrew) {
    return makeDecision(false, 'condition_threw', {
      rule: conditionThrew.rule,
      matchedRole: conditionThrew.role,
      matchedResource: args.resource,
      matchedAction: args.action,
      durationMs: nowMs() - start,
    });
  }
  if (asyncWarning) {
    return makeDecision(false, 'condition_failed', {
      durationMs: nowMs() - start,
      warning: 'async_condition_in_sync_check',
    });
  }
  return makeDecision(false, 'no_matching_rule', { durationMs: nowMs() - start });
}

/**
 * Async decision pass — same semantics but conditions may return Promises.
 */
export async function evaluateAsync(args: EvaluateArgs): Promise<Decision> {
  const start = nowMs();
  const candidates = collectCandidates(args);
  if (candidates.length === 0) {
    return makeDecision(false, 'no_matching_rule', { durationMs: nowMs() - start });
  }

  const precedence = args.compiled.options.precedence ?? 'deny';
  let conditionThrew: { rule: NormalizedRule; role: string; cause: unknown } | undefined;

  for (const c of candidates) {
    const outcome = await runConditionAsync(c.rule.condition, {
      subject: args.subject,
      target: args.target,
      context: args.context,
      tenantId: args.subject.tenantId,
      now: args.now,
    });

    if (outcome.kind === 'matched') {
      const allowed = c.rule.effect === 'allow';
      if (allowed) {
        return makeDecision(true, 'allowed_by_rule', {
          rule: c.rule,
          matchedRole: c.role,
          matchedResource: args.resource,
          matchedAction: args.action,
          ...(c.rule.fields ? { fields: c.rule.fields } : {}),
          durationMs: nowMs() - start,
        });
      }
      if (precedence === 'deny') {
        return makeDecision(false, 'denied_by_rule', {
          rule: c.rule,
          matchedRole: c.role,
          matchedResource: args.resource,
          matchedAction: args.action,
          durationMs: nowMs() - start,
        });
      }
      continue;
    }

    if (outcome.kind === 'threw') {
      conditionThrew ??= { rule: c.rule, role: c.role, cause: outcome.cause };
      continue;
    }
  }

  if (conditionThrew) {
    return makeDecision(false, 'condition_threw', {
      rule: conditionThrew.rule,
      matchedRole: conditionThrew.role,
      matchedResource: args.resource,
      matchedAction: args.action,
      durationMs: nowMs() - start,
    });
  }
  return makeDecision(false, 'no_matching_rule', { durationMs: nowMs() - start });
}

/**
 * Build the prioritized candidate list. A rule is a candidate when ALL three
 * of `(role, resource, action)` match. Ordering: priority desc, insertion
 * order asc.
 */
function collectCandidates(args: EvaluateArgs): readonly Candidate[] {
  const out: Candidate[] = [];
  for (const rule of args.compiled.rules) {
    if (!matchesAny(args.effectiveRoles, rule.roles)) continue;
    if (!matches(args.resource, rule.resources)) continue;
    if (!matches(args.action, rule.actions)) continue;

    const matchedRole = pickMatchedRole(args.effectiveRoles, rule.roles);
    out.push({ rule, role: matchedRole });
  }
  out.sort((a, b) => {
    if (a.rule.priority !== b.rule.priority) return b.rule.priority - a.rule.priority;
    return a.rule.order - b.rule.order;
  });
  return out;
}

function pickMatchedRole(
  effective: readonly string[],
  ruleRoles: readonly string[],
): string {
  const set = new Set(ruleRoles);
  for (const r of effective) {
    if (set.has(r)) return r;
  }
  return ruleRoles[0] ?? '';
}

const nowMs = (): number => {
  // performance.now() is available in Node 18+, browsers, Workers and Deno.
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
};
