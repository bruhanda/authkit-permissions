import { describe, expect, it } from 'vitest';
import { defineAsyncCondition, defineCondition } from '../core/conditions.js';
import {
  type ConditionMap,
  type EvalContext,
  type RuleEvalState,
  collectConditionRefs,
  evalRuleAsync,
  evalRuleSync,
} from '../core/evaluator.js';
import { PermissionError } from '../errors/base.js';
import type { ConditionArgs } from '../types/condition.js';

const args: ConditionArgs = {
  subject: { id: 'u1', roles: ['admin'] },
  resourceType: 'doc',
  action: 'read',
};

const buildCtx = (conditions: ConditionMap): EvalContext => ({
  conditions,
  args,
});

describe('collectConditionRefs', () => {
  it('should return empty list for true rule', () => {
    expect(collectConditionRefs(true)).toEqual([]);
  });

  it('should collect when reference', () => {
    expect(collectConditionRefs({ when: 'isOwner' })).toEqual(['isOwner']);
  });

  it('should collect allOf references', () => {
    expect(collectConditionRefs({ allOf: ['a', 'b'] })).toEqual(['a', 'b']);
  });

  it('should collect anyOf references', () => {
    expect(collectConditionRefs({ anyOf: ['a', 'b'] })).toEqual(['a', 'b']);
  });

  it('should collect not reference', () => {
    expect(collectConditionRefs({ not: 'a' })).toEqual(['a']);
  });

  it('should collect refs in nested rules', () => {
    expect(
      collectConditionRefs({
        allOf: [
          { anyOf: ['a', 'b'] },
          { not: { when: 'c' } },
        ],
      }),
    ).toEqual(['a', 'b', 'c']);
  });
});

describe('evalRuleSync', () => {
  it('should return true for the trivial true rule', () => {
    const state: RuleEvalState = {};
    expect(evalRuleSync(true, buildCtx({}), state)).toBe(true);
  });

  it('should evaluate a single condition', () => {
    const conditions: ConditionMap = {
      isAdmin: defineCondition(({ subject }) => subject.id === 'u1'),
    };
    const state: RuleEvalState = {};
    expect(evalRuleSync({ when: 'isAdmin' }, buildCtx(conditions), state)).toBe(true);
  });

  it('should record failed condition name on deny', () => {
    const conditions: ConditionMap = {
      no: defineCondition(() => false),
    };
    const state: RuleEvalState = {};
    expect(evalRuleSync({ when: 'no' }, buildCtx(conditions), state)).toBe(false);
    expect(state.failedCondition).toBe('no');
  });

  it('should evaluate allOf with short-circuit', () => {
    const conditions: ConditionMap = {
      a: defineCondition(() => true),
      b: defineCondition(() => false),
      c: defineCondition(() => {
        throw new Error('should not run');
      }),
    };
    const state: RuleEvalState = {};
    expect(evalRuleSync({ allOf: ['a', 'b', 'c'] }, buildCtx(conditions), state)).toBe(false);
  });

  it('should evaluate anyOf with short-circuit', () => {
    const conditions: ConditionMap = {
      a: defineCondition(() => false),
      b: defineCondition(() => true),
      c: defineCondition(() => {
        throw new Error('should not run');
      }),
    };
    const state: RuleEvalState = {};
    expect(evalRuleSync({ anyOf: ['a', 'b', 'c'] }, buildCtx(conditions), state)).toBe(true);
  });

  it('should accumulate failures from anyOf branches when all fail', () => {
    const conditions: ConditionMap = {
      a: defineCondition(() => false),
      b: defineCondition(() => false),
    };
    const state: RuleEvalState = {};
    expect(evalRuleSync({ anyOf: ['a', 'b'] }, buildCtx(conditions), state)).toBe(false);
    expect(state.failedCondition).toBeDefined();
  });

  it('should invert with not', () => {
    const conditions: ConditionMap = {
      yes: defineCondition(() => true),
      no: defineCondition(() => false),
    };
    expect(evalRuleSync({ not: 'no' }, buildCtx(conditions), {})).toBe(true);
    expect(evalRuleSync({ not: 'yes' }, buildCtx(conditions), {})).toBe(false);
  });

  it('should fail closed when not wraps a throwing condition', () => {
    const conditions: ConditionMap = {
      bang: defineCondition(() => {
        throw new Error('boom');
      }),
    };
    const state: RuleEvalState = {};
    expect(evalRuleSync({ not: 'bang' }, buildCtx(conditions), state)).toBe(false);
    expect(state.threwCondition).toBe('bang');
  });

  it('should record non-boolean condition result', () => {
    const conditions: ConditionMap = {
      odd: defineCondition(() => 'truthy' as unknown as boolean),
    };
    const state: RuleEvalState = {};
    expect(evalRuleSync({ when: 'odd' }, buildCtx(conditions), state)).toBe(false);
    expect(state.nonBooleanCondition).toBe('odd');
  });

  it('should throw UNKNOWN_CONDITION when reference is missing', () => {
    expect(() => evalRuleSync({ when: 'ghost' }, buildCtx({}), {})).toThrow(PermissionError);
    try {
      evalRuleSync({ when: 'ghost' }, buildCtx({}), {});
    } catch (err) {
      expect((err as PermissionError).code).toBe('UNKNOWN_CONDITION');
    }
  });

  it('should throw ASYNC_CONDITION_IN_SYNC_PATH when async is referenced', () => {
    const conditions: ConditionMap = {
      heavy: defineAsyncCondition(async () => true),
    };
    expect(() => evalRuleSync({ when: 'heavy' }, buildCtx(conditions), {})).toThrow(
      PermissionError,
    );
    try {
      evalRuleSync({ when: 'heavy' }, buildCtx(conditions), {});
    } catch (err) {
      expect((err as PermissionError).code).toBe('ASYNC_CONDITION_IN_SYNC_PATH');
    }
  });

  it('should evaluate a string-form node alias for when', () => {
    const conditions: ConditionMap = {
      yes: defineCondition(() => true),
    };
    expect(
      evalRuleSync({ allOf: ['yes'] }, buildCtx(conditions), {}),
    ).toBe(true);
  });
});

describe('evalRuleAsync', () => {
  it('should return true for the trivial true rule', async () => {
    await expect(evalRuleAsync(true, buildCtx({}), {})).resolves.toBe(true);
  });

  it('should evaluate sync conditions in async path', async () => {
    const conditions: ConditionMap = {
      yes: defineCondition(() => true),
    };
    await expect(
      evalRuleAsync({ when: 'yes' }, buildCtx(conditions), {}),
    ).resolves.toBe(true);
  });

  it('should evaluate async conditions', async () => {
    const conditions: ConditionMap = {
      yes: defineAsyncCondition(async () => true),
      no: defineAsyncCondition(async () => false),
    };
    await expect(evalRuleAsync({ when: 'yes' }, buildCtx(conditions), {})).resolves.toBe(true);
    await expect(evalRuleAsync({ when: 'no' }, buildCtx(conditions), {})).resolves.toBe(false);
  });

  it('should support untagged conditions as async', async () => {
    const conditions: ConditionMap = {
      yes: ((): Promise<boolean> => Promise.resolve(true)) as never,
    };
    await expect(evalRuleAsync({ when: 'yes' }, buildCtx(conditions), {})).resolves.toBe(true);
  });

  it('should evaluate allOf', async () => {
    const conditions: ConditionMap = {
      a: defineAsyncCondition(async () => true),
      b: defineAsyncCondition(async () => true),
      c: defineAsyncCondition(async () => false),
    };
    await expect(evalRuleAsync({ allOf: ['a', 'b'] }, buildCtx(conditions), {})).resolves.toBe(
      true,
    );
    await expect(evalRuleAsync({ allOf: ['a', 'c'] }, buildCtx(conditions), {})).resolves.toBe(
      false,
    );
  });

  it('should evaluate anyOf', async () => {
    const conditions: ConditionMap = {
      a: defineAsyncCondition(async () => false),
      b: defineAsyncCondition(async () => true),
    };
    await expect(evalRuleAsync({ anyOf: ['a', 'b'] }, buildCtx(conditions), {})).resolves.toBe(
      true,
    );
  });

  it('should accumulate failed conditions when all anyOf branches deny', async () => {
    const conditions: ConditionMap = {
      a: defineAsyncCondition(async () => false),
      b: defineAsyncCondition(async () => false),
    };
    const state: RuleEvalState = {};
    await expect(
      evalRuleAsync({ anyOf: ['a', 'b'] }, buildCtx(conditions), state),
    ).resolves.toBe(false);
    expect(state.failedCondition).toBeDefined();
  });

  it('should record threw condition and fail closed', async () => {
    const conditions: ConditionMap = {
      bang: defineAsyncCondition(async () => {
        throw new Error('boom');
      }),
    };
    const state: RuleEvalState = {};
    await expect(
      evalRuleAsync({ when: 'bang' }, buildCtx(conditions), state),
    ).resolves.toBe(false);
    expect(state.threwCondition).toBe('bang');
    expect((state.threwCause as Error).message).toBe('boom');
  });

  it('should record non-boolean condition result', async () => {
    const conditions: ConditionMap = {
      bad: defineAsyncCondition(async () => ({}) as unknown as boolean),
    };
    const state: RuleEvalState = {};
    await expect(evalRuleAsync({ when: 'bad' }, buildCtx(conditions), state)).resolves.toBe(false);
    expect(state.nonBooleanCondition).toBe('bad');
  });

  it('should fail closed when not wraps a throwing async condition', async () => {
    const conditions: ConditionMap = {
      bang: defineAsyncCondition(async () => {
        throw new Error('boom');
      }),
    };
    const state: RuleEvalState = {};
    await expect(
      evalRuleAsync({ not: 'bang' }, buildCtx(conditions), state),
    ).resolves.toBe(false);
    expect(state.threwCondition).toBe('bang');
  });

  it('should invert with not in async path', async () => {
    const conditions: ConditionMap = {
      yes: defineAsyncCondition(async () => true),
      no: defineAsyncCondition(async () => false),
    };
    await expect(evalRuleAsync({ not: 'no' }, buildCtx(conditions), {})).resolves.toBe(true);
    await expect(evalRuleAsync({ not: 'yes' }, buildCtx(conditions), {})).resolves.toBe(false);
  });

  it('should evaluate nested combinators', async () => {
    const conditions: ConditionMap = {
      a: defineAsyncCondition(async () => true),
      b: defineAsyncCondition(async () => false),
    };
    await expect(
      evalRuleAsync({ anyOf: [{ allOf: ['a', 'b'] }, 'a'] }, buildCtx(conditions), {}),
    ).resolves.toBe(true);
  });
});
