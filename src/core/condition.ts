import type { ConditionFn, DeclarativeCondition } from '../types/condition.js';
import type { ResourceInstance } from '../types/instances.js';
import type { Subject } from '../types/subject.js';
import { isDev, warnOnce } from '../utils/env.js';

/**
 * Outcome of evaluating a rule's condition. Wraps the boolean answer with
 * the diagnostics the evaluator needs.
 */
export type ConditionOutcome =
  | { kind: 'matched' }
  | { kind: 'failed' }
  | { kind: 'threw'; cause: unknown }
  | { kind: 'async_in_sync' };

const PROMISE_LIKE_KEYS = ['then'] as const;

const isPromiseLike = (value: unknown): value is Promise<unknown> => {
  if (value == null) return false;
  if (typeof value !== 'object' && typeof value !== 'function') return false;
  for (const k of PROMISE_LIKE_KEYS) {
    if (typeof (value as { then?: unknown }).then !== 'function') return false;
    if (k === 'then') return true;
  }
  return false;
};

/**
 * Resolve a declarative condition value against a subject — returning the
 * concrete value to compare to (used by `accessibleBy()`).
 */
export const resolveDeclarativeValue = (
  cond: DeclarativeCondition,
  subject: Subject,
): unknown | readonly unknown[] => {
  if (cond.kind === 'declarative-eq') {
    return typeof cond.value === 'function'
      ? (cond.value as (s: Subject) => unknown)(subject)
      : cond.value;
  }
  return typeof cond.values === 'function'
    ? (cond.values as (s: Subject) => readonly unknown[])(subject)
    : cond.values;
};

/**
 * Evaluate a declarative condition at runtime against a `target`.
 */
export const evaluateDeclarative = (
  cond: DeclarativeCondition,
  subject: Subject,
  target: ResourceInstance | undefined,
): boolean => {
  if (target == null) return false;
  const fieldValue = (target as Record<string, unknown>)[cond.field];
  const compare = resolveDeclarativeValue(cond, subject);
  if (cond.kind === 'declarative-eq') return fieldValue === compare;
  if (Array.isArray(compare)) {
    for (const v of compare as readonly unknown[]) {
      if (v === fieldValue) return true;
    }
  }
  return false;
};

/**
 * Run a sync rule condition. If the condition returns a Promise we cannot
 * await it from a sync caller — return `async_in_sync` and let the
 * evaluator surface it as `condition_failed`.
 */
export const runConditionSync = (
  fn: ConditionFn | DeclarativeCondition | undefined,
  args: {
    subject: Subject;
    target: ResourceInstance | undefined;
    context: Readonly<Record<string, unknown>>;
    tenantId: string | undefined;
    now: () => Date;
  },
): ConditionOutcome => {
  if (!fn) return { kind: 'matched' };
  try {
    if (typeof fn === 'function') {
      const result = fn({
        subject: args.subject,
        ...(args.target !== undefined ? { target: args.target } : {}),
        context: args.context,
        ...(args.tenantId !== undefined ? { tenantId: args.tenantId } : {}),
        now: args.now,
      });
      if (isPromiseLike(result)) return { kind: 'async_in_sync' };
      return coerceBoolean(result) ? { kind: 'matched' } : { kind: 'failed' };
    }
    return evaluateDeclarative(fn, args.subject, args.target)
      ? { kind: 'matched' }
      : { kind: 'failed' };
  } catch (cause) {
    return { kind: 'threw', cause };
  }
};

/**
 * Async variant — awaits any Promise the condition returns.
 */
export const runConditionAsync = async (
  fn: ConditionFn | DeclarativeCondition | undefined,
  args: {
    subject: Subject;
    target: ResourceInstance | undefined;
    context: Readonly<Record<string, unknown>>;
    tenantId: string | undefined;
    now: () => Date;
  },
): Promise<ConditionOutcome> => {
  if (!fn) return { kind: 'matched' };
  try {
    if (typeof fn === 'function') {
      const result = await fn({
        subject: args.subject,
        ...(args.target !== undefined ? { target: args.target } : {}),
        context: args.context,
        ...(args.tenantId !== undefined ? { tenantId: args.tenantId } : {}),
        now: args.now,
      });
      return coerceBoolean(result) ? { kind: 'matched' } : { kind: 'failed' };
    }
    return evaluateDeclarative(fn, args.subject, args.target)
      ? { kind: 'matched' }
      : { kind: 'failed' };
  } catch (cause) {
    return { kind: 'threw', cause };
  }
};

const coerceBoolean = (value: unknown): boolean => {
  if (typeof value === 'boolean') return value;
  if (isDev()) {
    warnOnce(
      'condition-non-boolean',
      '[@authkit/permissions] A condition returned a non-boolean value; coercing via Boolean().',
    );
  }
  return Boolean(value);
};
