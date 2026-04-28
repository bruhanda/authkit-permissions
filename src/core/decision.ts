import type { Decision, DecisionReason, MatchedRule } from '../types/decision.js';
import type { NormalizedRule } from '../types/policy.js';

/**
 * Build a `Decision` for a denied/allowed verdict. Keeping factory
 * functions here means the rest of the engine never has to remember
 * which fields are mandatory and which are optional.
 */
export const makeDecision = (
  allowed: boolean,
  reason: DecisionReason,
  extras?: {
    rule?: NormalizedRule;
    matchedRole?: string;
    matchedResource?: string;
    matchedAction?: string;
    fields?: readonly string[];
    durationMs?: number;
    warning?: Decision['warning'];
  },
): Decision => {
  const out: { -readonly [K in keyof Decision]: Decision[K] } = {
    allowed,
    reason,
  };
  if (extras?.rule) {
    const m: { -readonly [K in keyof MatchedRule]: MatchedRule[K] } = {
      role: extras.matchedRole ?? extras.rule.roles[0] ?? '',
      resource:
        extras.matchedResource ??
        (extras.rule.resources === '*' ? '*' : (extras.rule.resources[0] ?? '')),
      action:
        extras.matchedAction ??
        (extras.rule.actions === '*' ? '*' : (extras.rule.actions[0] ?? '')),
      effect: extras.rule.effect,
      priority: extras.rule.priority,
    };
    if (extras.rule.description !== undefined) {
      m.description = extras.rule.description;
    }
    out.matchedRule = m;
  }
  if (extras?.fields && extras.fields.length > 0) out.fields = extras.fields;
  if (extras?.durationMs !== undefined) out.durationMs = extras.durationMs;
  if (extras?.warning) out.warning = extras.warning;
  return out;
};

/** Shortcut for the very common "no matching rule" path. */
export const denyNoMatch = (durationMs?: number): Decision =>
  durationMs !== undefined
    ? makeDecision(false, 'no_matching_rule', { durationMs })
    : makeDecision(false, 'no_matching_rule');

/** Shortcut for the equally common "subject has no roles" path. */
export const denyNoRoles = (durationMs?: number): Decision =>
  durationMs !== undefined
    ? makeDecision(false, 'subject_has_no_roles', { durationMs })
    : makeDecision(false, 'subject_has_no_roles');
