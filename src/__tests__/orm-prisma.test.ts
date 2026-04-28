import { describe, expect, it } from 'vitest';
import { createPrismaRoleAdapter, toPrismaWhere } from '../orm/prisma/index.js';
import type { FilterAst } from '../types/filter.js';
import type { PrismaClientLike } from '../orm/prisma/index.js';

describe('toPrismaWhere', () => {
  it('should convert true to empty where', () => {
    expect(toPrismaWhere({ kind: 'true' })).toEqual({});
  });

  it('should convert opaque to empty where (post-fetch check)', () => {
    expect(toPrismaWhere({ kind: 'opaque', conditionName: 'isOwner' })).toEqual({});
  });

  it('should convert false to a sentinel always-false clause', () => {
    const out = toPrismaWhere({ kind: 'false' }) as {
      AND: Array<{ id: { equals: string } }>;
    };
    expect(out.AND).toHaveLength(1);
    expect(out.AND[0]?.id?.equals).toContain('__authkit_never__');
  });

  it('should convert eq to {field:{equals}}', () => {
    expect(toPrismaWhere({ kind: 'eq', field: 'ownerId', value: 'u1' })).toEqual({
      ownerId: { equals: 'u1' },
    });
  });

  it('should convert in to {field:{in}}', () => {
    expect(
      toPrismaWhere({ kind: 'in', field: 'tenantId', values: ['t1', 't2'] }),
    ).toEqual({ tenantId: { in: ['t1', 't2'] } });
  });

  it('should convert and to AND with mapped children', () => {
    const ast: FilterAst = {
      kind: 'and',
      nodes: [
        { kind: 'eq', field: 'a', value: 1 },
        { kind: 'eq', field: 'b', value: 2 },
      ],
    };
    expect(toPrismaWhere(ast)).toEqual({
      AND: [{ a: { equals: 1 } }, { b: { equals: 2 } }],
    });
  });

  it('should convert or to OR with mapped children', () => {
    const ast: FilterAst = {
      kind: 'or',
      nodes: [
        { kind: 'eq', field: 'a', value: 1 },
        { kind: 'eq', field: 'b', value: 2 },
      ],
    };
    expect(toPrismaWhere(ast)).toEqual({
      OR: [{ a: { equals: 1 } }, { b: { equals: 2 } }],
    });
  });

  it('should convert not to NOT', () => {
    expect(
      toPrismaWhere({ kind: 'not', node: { kind: 'eq', field: 'archived', value: true } }),
    ).toEqual({ NOT: { archived: { equals: true } } });
  });
});

describe('createPrismaRoleAdapter', () => {
  it('should load roles via findMany on the configured model', async () => {
    const prisma: PrismaClientLike = {
      membership: {
        findMany: async () => [
          { role: 'admin' },
          { role: 'member' },
          { role: 42 },
        ],
      },
    };
    const adapter = createPrismaRoleAdapter(prisma, {
      membershipModel: 'membership',
      userField: 'userId',
      tenantField: 'tenantId',
      roleField: 'role',
    });
    const subject = await adapter.loadSubject({ userId: 'u1', tenantId: 't1' });
    expect(subject.id).toBe('u1');
    expect(subject.tenantId).toBe('t1');
    expect(subject.roles).toEqual(['admin', 'member']);
  });

  it('should pass user/tenant fields into the where clause', async () => {
    let captured: unknown;
    const prisma: PrismaClientLike = {
      membership: {
        findMany: async (args) => {
          captured = args;
          return [];
        },
      },
    };
    const adapter = createPrismaRoleAdapter(prisma, {
      membershipModel: 'membership',
      userField: 'userId',
      tenantField: 'tenantId',
      roleField: 'role',
    });
    await adapter.loadSubject({ userId: 'u1', tenantId: 't1' });
    expect(captured).toEqual({
      where: { userId: 'u1', tenantId: 't1' },
      select: { role: true },
    });
  });

  it('should throw when the configured model is missing on the client', async () => {
    const prisma = {} as PrismaClientLike;
    const adapter = createPrismaRoleAdapter(prisma, {
      membershipModel: 'membership',
      userField: 'userId',
      tenantField: 'tenantId',
      roleField: 'role',
    });
    await expect(
      adapter.loadSubject({ userId: 'u1', tenantId: 't1' }),
    ).rejects.toThrow(/membership/);
  });
});
