import { describe, expect, it } from 'vitest';
import { createMongooseRoleAdapter, toMongoFilter } from '../orm/mongoose/index.js';
import type { FilterAst } from '../types/filter.js';

describe('toMongoFilter', () => {
  it('should convert true to empty filter', () => {
    expect(toMongoFilter({ kind: 'true' })).toEqual({});
  });

  it('should convert opaque to empty filter (post-fetch check)', () => {
    expect(toMongoFilter({ kind: 'opaque', conditionName: 'x' })).toEqual({});
  });

  it('should convert false to a $expr always-false', () => {
    expect(toMongoFilter({ kind: 'false' })).toEqual({
      $expr: { $eq: [false, true] },
    });
  });

  it('should convert eq to {field: value}', () => {
    expect(toMongoFilter({ kind: 'eq', field: 'ownerId', value: 'u1' })).toEqual({
      ownerId: 'u1',
    });
  });

  it('should convert in to {field: {$in}}', () => {
    expect(
      toMongoFilter({ kind: 'in', field: 'tenantId', values: ['a', 'b'] }),
    ).toEqual({ tenantId: { $in: ['a', 'b'] } });
  });

  it('should convert and to $and', () => {
    const ast: FilterAst = {
      kind: 'and',
      nodes: [
        { kind: 'eq', field: 'a', value: 1 },
        { kind: 'eq', field: 'b', value: 2 },
      ],
    };
    expect(toMongoFilter(ast)).toEqual({
      $and: [{ a: 1 }, { b: 2 }],
    });
  });

  it('should convert or to $or', () => {
    const ast: FilterAst = {
      kind: 'or',
      nodes: [
        { kind: 'eq', field: 'a', value: 1 },
        { kind: 'eq', field: 'b', value: 2 },
      ],
    };
    expect(toMongoFilter(ast)).toEqual({
      $or: [{ a: 1 }, { b: 2 }],
    });
  });

  it('should convert not to $nor', () => {
    expect(
      toMongoFilter({ kind: 'not', node: { kind: 'eq', field: 'archived', value: true } }),
    ).toEqual({ $nor: [{ archived: true }] });
  });
});

describe('createMongooseRoleAdapter', () => {
  it('should load roles from the query closure', async () => {
    const adapter = createMongooseRoleAdapter({
      query: async () => [{ role: 'admin' }, { role: undefined as never }, { role: 'member' }],
    });
    const subject = await adapter.loadSubject({ userId: 'u1', tenantId: 't1' });
    expect(subject.roles).toEqual(['admin', 'member']);
  });

  it('should forward userId and tenantId arguments', async () => {
    let captured: { userId?: string; tenantId?: string } = {};
    const adapter = createMongooseRoleAdapter({
      query: async (args) => {
        captured = args;
        return [];
      },
    });
    await adapter.loadSubject({ userId: 'u', tenantId: 't' });
    expect(captured).toEqual({ userId: 'u', tenantId: 't' });
  });
});
