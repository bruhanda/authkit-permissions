import { describe, expect, it } from 'vitest';
import { createDrizzleRoleAdapter, toDrizzleWhere } from '../orm/drizzle/index.js';
import type { FilterAst } from '../types/filter.js';

describe('toDrizzleWhere', () => {
  it('should convert true', () => {
    expect(toDrizzleWhere({ kind: 'true' })).toEqual({ kind: 'true' });
  });

  it('should convert false', () => {
    expect(toDrizzleWhere({ kind: 'false' })).toEqual({ kind: 'false' });
  });

  it('should convert eq to {column,value}', () => {
    expect(toDrizzleWhere({ kind: 'eq', field: 'ownerId', value: 'u1' })).toEqual({
      kind: 'eq',
      column: 'ownerId',
      value: 'u1',
    });
  });

  it('should convert in to {column,values}', () => {
    expect(
      toDrizzleWhere({ kind: 'in', field: 'tenantId', values: ['t1', 't2'] }),
    ).toEqual({ kind: 'in', column: 'tenantId', values: ['t1', 't2'] });
  });

  it('should recurse on and/or/not', () => {
    const ast: FilterAst = {
      kind: 'and',
      nodes: [
        { kind: 'or', nodes: [{ kind: 'eq', field: 'a', value: 1 }] },
        { kind: 'not', node: { kind: 'eq', field: 'b', value: 2 } },
      ],
    };
    expect(toDrizzleWhere(ast)).toEqual({
      kind: 'and',
      nodes: [
        { kind: 'or', nodes: [{ kind: 'eq', column: 'a', value: 1 }] },
        { kind: 'not', node: { kind: 'eq', column: 'b', value: 2 } },
      ],
    });
  });

  it('should pass opaque conditions through', () => {
    expect(toDrizzleWhere({ kind: 'opaque', conditionName: 'isOwner' })).toEqual({
      kind: 'opaque',
      conditionName: 'isOwner',
    });
  });
});

describe('createDrizzleRoleAdapter', () => {
  it('should load roles via the supplied query closure', async () => {
    const adapter = createDrizzleRoleAdapter({
      query: async () => [{ role: 'admin' }, { role: 'member' }, { role: 99 as never }],
    });
    const subject = await adapter.loadSubject({ userId: 'u1', tenantId: 't1' });
    expect(subject.roles).toEqual(['admin', 'member']);
    expect(subject.id).toBe('u1');
    expect(subject.tenantId).toBe('t1');
  });

  it('should pass userId and tenantId into the query', async () => {
    let captured: { userId?: string; tenantId?: string } = {};
    const adapter = createDrizzleRoleAdapter({
      query: async (args) => {
        captured = args;
        return [];
      },
    });
    await adapter.loadSubject({ userId: 'u1', tenantId: 't1' });
    expect(captured).toEqual({ userId: 'u1', tenantId: 't1' });
  });
});
