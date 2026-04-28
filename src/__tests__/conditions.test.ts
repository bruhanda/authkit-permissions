import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  defineAsyncCondition,
  defineCondition,
  getConditionFilter,
  isAsyncCondition,
  isSyncCondition,
} from '../core/conditions.js';
import type {
  ConditionArgs,
  TaggedAsyncCondition,
  TaggedSyncCondition,
} from '../types/condition.js';
import type { FilterAst } from '../types/filter.js';

describe('defineCondition', () => {
  it('should tag a sync predicate with __authkitMode = sync', () => {
    const cond = defineCondition(({ subject }) => subject.id === 'a');
    expect(isSyncCondition(cond)).toBe(true);
    expect(isAsyncCondition(cond)).toBe(false);
  });

  it('should preserve the predicate behaviour at runtime', () => {
    const cond = defineCondition(({ subject }) => subject.id === 'a');
    const args: ConditionArgs = {
      subject: { id: 'a', roles: [] },
      resourceType: 'doc',
      action: 'read',
    };
    expect(cond(args)).toBe(true);
    expect(cond({ ...args, subject: { id: 'b', roles: [] } })).toBe(false);
  });

  it('should attach a filter hint when provided in two-arg form', () => {
    const filter = (): FilterAst => ({ kind: 'eq', field: 'ownerId', value: 'a' });
    const cond = defineCondition(({ subject }) => subject.id === 'a', { filter });
    expect(getConditionFilter(cond)).toBe(filter);
  });

  it('should accept resource-type form and attach filter hint', () => {
    const filter = (subject: { id: string }): FilterAst => ({
      kind: 'eq',
      field: 'ownerId',
      value: subject.id,
    });
    const cond = defineCondition(
      'document',
      ({ subject, resource }) => resource?.ownerId === subject.id,
      { filter },
    );
    expect(isSyncCondition(cond)).toBe(true);
    expect(getConditionFilter(cond)).toBe(filter);
  });

  it('should leave filter undefined when no hint is supplied', () => {
    const cond = defineCondition(() => true);
    expect(getConditionFilter(cond)).toBeUndefined();
  });

  it('should preserve return type as TaggedSyncCondition', () => {
    const cond = defineCondition<ConditionArgs>(() => true);
    expectTypeOf(cond).toMatchTypeOf<TaggedSyncCondition<ConditionArgs>>();
  });

  it('should make __authkitMode non-enumerable and non-writable', () => {
    const cond = defineCondition(() => true);
    const desc = Object.getOwnPropertyDescriptor(cond, '__authkitMode');
    expect(desc?.enumerable).toBe(false);
    expect(desc?.configurable).toBe(false);
    expect(desc?.writable).toBe(false);
  });
});

describe('defineAsyncCondition', () => {
  it('should tag an async predicate with __authkitMode = async', () => {
    const cond = defineAsyncCondition(async () => true);
    expect(isAsyncCondition(cond)).toBe(true);
    expect(isSyncCondition(cond)).toBe(false);
  });

  it('should preserve the predicate behaviour at runtime', async () => {
    const cond = defineAsyncCondition(async ({ subject }) => subject.id === 'a');
    const args: ConditionArgs = {
      subject: { id: 'a', roles: [] },
      resourceType: 'doc',
      action: 'read',
    };
    await expect(cond(args)).resolves.toBe(true);
  });

  it('should attach a filter hint in two-arg form', () => {
    const filter = (): FilterAst => ({ kind: 'true' });
    const cond = defineAsyncCondition(async () => true, { filter });
    expect(getConditionFilter(cond)).toBe(filter);
  });

  it('should accept resource-type form and attach filter hint', () => {
    const filter = (): FilterAst => ({ kind: 'true' });
    const cond = defineAsyncCondition('document', async () => true, { filter });
    expect(isAsyncCondition(cond)).toBe(true);
    expect(getConditionFilter(cond)).toBe(filter);
  });

  it('should preserve return type as TaggedAsyncCondition', () => {
    const cond = defineAsyncCondition<ConditionArgs>(async () => true);
    expectTypeOf(cond).toMatchTypeOf<TaggedAsyncCondition<ConditionArgs>>();
  });
});

describe('isSyncCondition / isAsyncCondition', () => {
  it('should report false for an untagged plain function', () => {
    const fn = ((): boolean => true) as unknown as TaggedSyncCondition;
    expect(isSyncCondition(fn)).toBe(false);
    expect(isAsyncCondition(fn)).toBe(false);
  });
});
