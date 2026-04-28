import { PermissionError } from '../errors/base.js';
import { ERROR_CODES } from '../errors/codes.js';
import { isDev } from '../utils/env.js';
import type { ConditionArgs, ConditionEntry } from '../types/condition.js';
import type { RuleDef } from '../types/policy.js';
import { isSyncCondition } from './conditions.js';

/**
 * Map of condition name → resolved condition function (with policy
 * defaults merged with `EnforcerOptions.conditions` overrides).
 */
export type ConditionMap = Record<string, ConditionEntry>;

/** Mutable trace state populated as a rule is walked. */
export interface RuleEvalState {
  /** First condition that returned a non-boolean value. */
  nonBooleanCondition?: string;
  /** Most recent condition that returned `false`. */
  failedCondition?: string;
  /** First condition that threw / rejected. */
  threwCondition?: string;
  /** Original error captured from the throwing condition. */
  threwCause?: unknown;
}

/** Evaluation context shared by the sync and async walkers. */
export interface EvalContext {
  readonly conditions: ConditionMap;
  readonly args: ConditionArgs;
}

/** Walk a `RuleDef` and collect every condition name it references. */
export function collectConditionRefs(rule: RuleDef): string[] {
  const out: string[] = [];
  const walk = (node: RuleDef | string): void => {
    if (node === true) return;
    if (typeof node === 'string') {
      out.push(node);
      return;
    }
    if ('when' in node) out.push(node.when);
    else if ('allOf' in node) for (const part of node.allOf) walk(part);
    else if ('anyOf' in node) for (const part of node.anyOf) walk(part);
    else if ('not' in node) walk(node.not);
  };
  walk(rule);
  return out;
}

/**
 * Evaluate a rule **synchronously**.
 *
 * Throws `PermissionError(ASYNC_CONDITION_IN_SYNC_PATH)` when the rule
 * references any condition that is not tagged sync — surfaces the bug
 * at call time instead of via a silent allow / deny (plan §9.2.7).
 *
 * @param rule - the rule node.
 * @param ctx - resolved condition map and per-call args.
 * @param state - mutable trace populated for the audit reason picker.
 * @returns `true` when the rule grants access.
 * @throws {@link PermissionError} `ASYNC_CONDITION_IN_SYNC_PATH`,
 *   `UNKNOWN_CONDITION`.
 */
export function evalRuleSync(
  rule: RuleDef,
  ctx: EvalContext,
  state: RuleEvalState,
): boolean {
  return walkSync(rule, ctx, state);
}

/**
 * Evaluate a rule **asynchronously**. Catches throws / rejections from
 * conditions and records them in `state` (the engine then denies and
 * audits with `cause` — never re-throws to the caller).
 */
export async function evalRuleAsync(
  rule: RuleDef,
  ctx: EvalContext,
  state: RuleEvalState,
): Promise<boolean> {
  return walkAsync(rule, ctx, state);
}

function walkSync(node: RuleDef | string, ctx: EvalContext, state: RuleEvalState): boolean {
  if (node === true) return true;
  if (typeof node === 'string') return runOneSync(node, ctx, state);
  if ('when' in node) return runOneSync(node.when, ctx, state);
  if ('allOf' in node) {
    for (const part of node.allOf) {
      if (!walkSync(part, ctx, state)) return false;
    }
    return true;
  }
  if ('anyOf' in node) {
    let anyPassed = false;
    for (const part of node.anyOf) {
      const inner: RuleEvalState = {};
      if (walkSync(part, ctx, inner)) {
        anyPassed = true;
        break;
      }
    }
    return anyPassed;
  }
  // `not`
  const inner: RuleEvalState = {};
  const result = walkSync(node.not, ctx, inner);
  return !result;
}

async function walkAsync(
  node: RuleDef | string,
  ctx: EvalContext,
  state: RuleEvalState,
): Promise<boolean> {
  if (node === true) return true;
  if (typeof node === 'string') return runOneAsync(node, ctx, state);
  if ('when' in node) return runOneAsync(node.when, ctx, state);
  if ('allOf' in node) {
    for (const part of node.allOf) {
      const ok = await walkAsync(part, ctx, state);
      if (!ok) return false;
    }
    return true;
  }
  if ('anyOf' in node) {
    for (const part of node.anyOf) {
      const inner: RuleEvalState = {};
      const ok = await walkAsync(part, ctx, inner);
      if (ok) return true;
      if (state.failedCondition === undefined && inner.failedCondition !== undefined) {
        state.failedCondition = inner.failedCondition;
      }
    }
    return false;
  }
  // `not`
  const inner: RuleEvalState = {};
  const ok = await walkAsync(node.not, ctx, inner);
  if (inner.threwCondition !== undefined) {
    state.threwCondition = inner.threwCondition;
    state.threwCause = inner.threwCause;
    return false;
  }
  return !ok;
}

function lookup(name: string, ctx: EvalContext): ConditionEntry {
  const fn = ctx.conditions[name];
  if (fn === undefined) {
    throw new PermissionError(
      ERROR_CODES.UNKNOWN_CONDITION,
      `Unknown condition "${name}" referenced from a rule`,
      { conditionName: name },
    );
  }
  return fn;
}

function runOneSync(name: string, ctx: EvalContext, state: RuleEvalState): boolean {
  const fn = lookup(name, ctx);
  if (!isSyncCondition(fn)) {
    throw new PermissionError(
      ERROR_CODES.ASYNC_CONDITION_IN_SYNC_PATH,
      `Condition "${name}" is not tagged sync; use defineCondition() or call enforcer.check() instead of checkSync()`,
      { conditionName: name },
    );
  }
  let value: unknown;
  try {
    value = (fn as (a: ConditionArgs) => boolean)(ctx.args);
  } catch (err) {
    state.threwCondition = name;
    state.threwCause = err;
    return false;
  }
  if (value === true) return true;
  if (value !== false) {
    state.nonBooleanCondition = name;
    if (isDev()) {
      // eslint-disable-next-line no-console
      console.warn(
        `[authkit/permissions] Condition "${name}" returned a non-boolean value (${typeof value}); treating as deny.`,
      );
    }
  } else {
    state.failedCondition = name;
  }
  return false;
}

async function runOneAsync(
  name: string,
  ctx: EvalContext,
  state: RuleEvalState,
): Promise<boolean> {
  const fn = lookup(name, ctx);
  let value: unknown;
  try {
    value = await (fn as (a: ConditionArgs) => boolean | Promise<boolean>)(ctx.args);
  } catch (err) {
    state.threwCondition = name;
    state.threwCause = err;
    return false;
  }
  if (value === true) return true;
  if (value !== false) {
    state.nonBooleanCondition = name;
    if (isDev()) {
      // eslint-disable-next-line no-console
      console.warn(
        `[authkit/permissions] Condition "${name}" returned a non-boolean value (${typeof value}); treating as deny.`,
      );
    }
  } else {
    state.failedCondition = name;
  }
  return false;
}
