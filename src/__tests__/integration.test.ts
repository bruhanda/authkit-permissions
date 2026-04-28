import { describe, expect, it } from 'vitest';
import {
  ERROR_CODES,
  PermissionError,
  composeAudit,
  createEnforcer,
  createSubject,
  defineAsyncCondition,
  defineCondition,
  definePolicy,
  isAsyncCondition,
  isSyncCondition,
} from '../index.js';
import { jsonFormatter, withTiming } from '../audit/index.js';
import { createPolicyBuilder } from '../builder/index.js';
import { toPrismaWhere } from '../orm/prisma/index.js';
import { toMongoFilter } from '../orm/mongoose/index.js';
import { toDrizzleWhere } from '../orm/drizzle/index.js';
import type { AuditEvent } from '../types/audit.js';

describe('end-to-end policy + enforcer + audit + ORM lowering', () => {
  it('should support a complete RBAC + ABAC + cross-tenant flow', async () => {
    const isOwner = defineCondition(({ subject, resource }) => {
      const r = resource as { ownerId?: string } | undefined;
      return r?.ownerId === subject.id;
    }, {
      filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }),
    });
    const sameTenant = defineCondition(({ subject, resource }) => {
      const r = resource as { tenantId?: string } | undefined;
      return r?.tenantId === subject.tenantId;
    }, {
      filter: (subject) => ({ kind: 'eq', field: 'tenantId', value: subject.tenantId }),
    });
    const isCollaborator = defineAsyncCondition(async ({ subject, resource }) => {
      const r = resource as { collaborators?: ReadonlyArray<string> } | undefined;
      return r?.collaborators?.includes(subject.id) ?? false;
    });

    const policy = definePolicy({
      version: 'v1',
      roles: {
        superAdmin: { extends: ['admin'], crossTenant: true },
        admin: { extends: ['member'] },
        member: { extends: ['viewer'] },
        viewer: {},
      },
      resources: {
        document: { actions: ['read', 'update', 'delete', 'create'] },
      },
      conditions: { isOwner, sameTenant, isCollaborator },
      permissions: {
        viewer: {
          document: {
            read: { allOf: ['sameTenant'] },
          },
        },
        member: {
          document: {
            update: { anyOf: ['isOwner', 'isCollaborator'] },
            create: { allOf: ['sameTenant'] },
          },
        },
        admin: {
          document: { delete: { rule: { when: 'sameTenant' }, priority: 5 } },
        },
        superAdmin: {
          document: ['*'],
        },
      },
    });

    expect(isSyncCondition(isOwner)).toBe(true);
    expect(isAsyncCondition(isCollaborator)).toBe(true);

    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, {
      audit: composeAudit((event) => {
        events.push(event);
      }),
    });

    const member = createSubject({ id: 'u-m', roles: ['member'] as const, tenantId: 't1' });
    const admin = createSubject({ id: 'u-a', roles: ['admin'] as const, tenantId: 't1' });
    const sa = createSubject({ id: 'u-s', roles: ['superAdmin'] as const, tenantId: 't1' });

    await expect(
      enforcer.check({
        subject: member,
        resource: 'document',
        action: 'read',
        data: { ownerId: 'someone', tenantId: 't1' },
      }),
    ).resolves.toBe(true);

    await expect(
      enforcer.check({
        subject: member,
        resource: 'document',
        action: 'update',
        data: { ownerId: 'u-m', tenantId: 't1' },
      }),
    ).resolves.toBe(true);

    await expect(
      enforcer.check({
        subject: member,
        resource: 'document',
        action: 'update',
        data: { ownerId: 'someone', tenantId: 't1', collaborators: ['u-m'] },
      }),
    ).resolves.toBe(true);

    await expect(
      enforcer.check({
        subject: member,
        resource: 'document',
        action: 'delete',
        data: { ownerId: 'u-m', tenantId: 't1' },
      }),
    ).resolves.toBe(false);

    await enforcer.enforce({
      subject: admin,
      resource: 'document',
      action: 'delete',
      data: { tenantId: 't1' },
    });

    await expect(
      enforcer.check({
        subject: sa,
        resource: 'document',
        action: 'read',
        data: { tenantId: 'other-tenant' },
        tenantId: 'other-tenant',
        allowCrossTenant: true,
      }),
    ).resolves.toBe(true);

    expect(events.length).toBeGreaterThan(0);
    const last = events.at(-1)!;
    expect(last.crossTenant).toBe(true);
    const json = jsonFormatter(last);
    expect(JSON.parse(json).version).toBe('v1');
  });

  it('should integrate accessibleBy filter lowering across all ORMs', () => {
    const isOwner = defineCondition(() => true, {
      filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }),
    });
    const sameTenant = defineCondition(() => true, {
      filter: (subject) => ({ kind: 'eq', field: 'tenantId', value: subject.tenantId }),
    });
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { isOwner, sameTenant },
      permissions: {
        m: {
          d: { read: { allOf: ['isOwner', 'sameTenant'] } },
        },
      },
    });
    const enforcer = createEnforcer(policy);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = enforcer.accessibleBy({ subject, resource: 'd', action: 'read' });
    expect(toPrismaWhere(ast)).toEqual({
      AND: [{ ownerId: { equals: 'u' } }, { tenantId: { equals: 't1' } }],
    });
    expect(toMongoFilter(ast)).toEqual({
      $and: [{ ownerId: 'u' }, { tenantId: 't1' }],
    });
    expect(toDrizzleWhere(ast)).toEqual({
      kind: 'and',
      nodes: [
        { kind: 'eq', column: 'ownerId', value: 'u' },
        { kind: 'eq', column: 'tenantId', value: 't1' },
      ],
    });
  });

  it('should expose ERROR_CODES and surface PermissionError in expected places', async () => {
    expect(ERROR_CODES.FORBIDDEN).toBe('FORBIDDEN');
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      permissions: { m: { d: ['read'] } },
    });
    const enforcer = createEnforcer(policy);
    const noTenant = createSubject({ id: 'u', roles: ['m'] as const });
    await expect(
      enforcer.enforce({ subject: noTenant, resource: 'd', action: 'read' }),
    ).rejects.toBeInstanceOf(PermissionError);
  });

  it('should let the fluent builder produce the same enforceable policy', async () => {
    const policy = createPolicyBuilder()
      .role('m')
      .resource('d', ['read'])
      .permit('m', 'd', ['read'])
      .build();
    const enforcer = createEnforcer(policy);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    await expect(
      enforcer.check({ subject, resource: 'd', action: 'read' }),
    ).resolves.toBe(true);
  });

  it('should integrate withTiming around an audit hook', async () => {
    const samples: Array<{ ms: number; reason: string; decision: string }> = [];
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      permissions: { m: { d: ['read'] } },
    });
    const audit = withTiming(() => undefined, (s) => samples.push(s));
    const enforcer = createEnforcer(policy, { audit });
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    await enforcer.check({ subject, resource: 'd', action: 'read' });
    expect(samples).toHaveLength(1);
    expect(samples[0]?.decision).toBe('allow');
  });
});
