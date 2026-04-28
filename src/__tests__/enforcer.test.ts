import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { defineAsyncCondition, defineCondition } from '../core/conditions.js';
import { createEnforcer } from '../core/enforcer.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';
import { PermissionError } from '../errors/base.js';
import type { AuditEvent } from '../types/audit.js';

const buildPolicy = () =>
  definePolicy({
    version: 'v1',
    roles: {
      superAdmin: { crossTenant: true, extends: ['admin'] },
      admin: { extends: ['member'] },
      member: {},
      guest: {},
    },
    resources: {
      document: { actions: ['read', 'update', 'delete', 'create'] },
      post: { actions: ['read', 'update'] },
    },
    conditions: {
      isOwner: defineCondition(({ subject, resource }) => {
        const r = resource as { ownerId?: string } | undefined;
        return r?.ownerId === subject.id;
      }),
      sameTenant: defineCondition(({ subject, resource }) => {
        const r = resource as { tenantId?: string } | undefined;
        return r?.tenantId === subject.tenantId;
      }),
      asyncCheck: defineAsyncCondition(async () => true),
      asyncFail: defineAsyncCondition(async () => false),
      threwSync: defineCondition(() => {
        throw new Error('boom');
      }),
      threwAsync: defineAsyncCondition(async () => {
        throw new Error('async boom');
      }),
      nonBoolSync: defineCondition(() => 'truthy' as unknown as boolean),
      nonBoolAsync: defineAsyncCondition(async () => 'truthy' as unknown as boolean),
    },
    permissions: {
      member: {
        document: {
          read: true,
          update: { when: 'isOwner' },
        },
        post: ['read'],
      },
      admin: {
        document: {
          delete: { rule: { when: 'isOwner' }, priority: 5 },
          create: true,
        },
        post: ['*'],
      },
      superAdmin: {
        document: ['read', 'update', 'delete', 'create'],
      },
      guest: {},
    },
  });

const member = createSubject({ id: 'u-member', roles: ['member'] as const, tenantId: 't1' });
const admin = createSubject({ id: 'u-admin', roles: ['admin'] as const, tenantId: 't1' });
const sa = createSubject({ id: 'u-sa', roles: ['superAdmin'] as const, tenantId: 't1' });
const noRoles = createSubject({ id: 'u-none', roles: [] as const, tenantId: 't1' });

describe('createEnforcer.check', () => {
  let policy: ReturnType<typeof buildPolicy>;
  beforeEach(() => {
    policy = buildPolicy();
  });

  it('should allow when a rule grants the action', async () => {
    const enforcer = createEnforcer(policy);
    await expect(
      enforcer.check({ subject: member, resource: 'document', action: 'read' }),
    ).resolves.toBe(true);
  });

  it('should deny when no rule matches', async () => {
    const enforcer = createEnforcer(policy);
    await expect(
      enforcer.check({ subject: member, resource: 'document', action: 'create' }),
    ).resolves.toBe(false);
  });

  it('should evaluate ABAC conditions', async () => {
    const enforcer = createEnforcer(policy);
    await expect(
      enforcer.check({
        subject: member,
        resource: 'document',
        action: 'update',
        data: { ownerId: 'u-member' },
      }),
    ).resolves.toBe(true);
    await expect(
      enforcer.check({
        subject: member,
        resource: 'document',
        action: 'update',
        data: { ownerId: 'someone-else' },
      }),
    ).resolves.toBe(false);
  });

  it('should expand wildcard ["*"] to every action on the resource', async () => {
    const enforcer = createEnforcer(policy);
    await expect(
      enforcer.check({ subject: admin, resource: 'post', action: 'update' }),
    ).resolves.toBe(true);
    await expect(
      enforcer.check({ subject: admin, resource: 'post', action: 'read' }),
    ).resolves.toBe(true);
  });

  it('should inherit member rules into admin via extends', async () => {
    const enforcer = createEnforcer(policy);
    await expect(
      enforcer.check({ subject: admin, resource: 'document', action: 'read' }),
    ).resolves.toBe(true);
  });

  it('should deny with no_roles when subject has zero roles', async () => {
    const enforcer = createEnforcer(policy);
    const events: AuditEvent[] = [];
    const e2 = createEnforcer(policy, { audit: (event) => events.push(event) });
    await expect(
      e2.check({ subject: noRoles, resource: 'document', action: 'read' }),
    ).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('no_roles');
  });

  it('should deny with unknown_role_on_subject when role is not in policy', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    const subject = createSubject({
      id: 'u',
      roles: ['ghost'] as const,
      tenantId: 't1',
    });
    await expect(
      enforcer.check({
        subject: subject as never,
        resource: 'document',
        action: 'read',
      }),
    ).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('unknown_role_on_subject');
  });

  it('should not allow forged toString role to bypass unknown-role check', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    const subject = { id: 'u', roles: ['toString'] as ReadonlyArray<string>, tenantId: 't1' };
    await expect(
      enforcer.check({ subject: subject as never, resource: 'document', action: 'read' }),
    ).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('unknown_role_on_subject');
  });

  it('should throw TENANT_REQUIRED when subject has no tenant under strictTenant', async () => {
    const enforcer = createEnforcer(policy);
    const subject = createSubject({ id: 'u', roles: ['member'] as const });
    await expect(
      enforcer.check({ subject, resource: 'document', action: 'read' }),
    ).rejects.toThrow(PermissionError);
  });

  it('should not throw when strictTenant is disabled', async () => {
    const enforcer = createEnforcer(policy, { strictTenant: false });
    const subject = createSubject({ id: 'u', roles: ['member'] as const });
    await expect(
      enforcer.check({ subject, resource: 'document', action: 'read' }),
    ).resolves.toBe(true);
  });

  it('should treat empty-string tenantId as missing under strictTenant', async () => {
    const enforcer = createEnforcer(policy);
    const subject = createSubject({ id: 'u', roles: ['member'] as const, tenantId: '' });
    try {
      await enforcer.check({ subject, resource: 'document', action: 'read' });
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      expect((err as PermissionError).code).toBe('TENANT_REQUIRED');
    }
  });

  it('should deny tenant_mismatch when arg tenant differs and role lacks crossTenant', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await expect(
      enforcer.check({
        subject: admin,
        resource: 'document',
        action: 'read',
        tenantId: 'other',
      }),
    ).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('tenant_mismatch');
  });

  it('should allow cross-tenant when both role and per-call flag are set', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await expect(
      enforcer.check({
        subject: sa,
        resource: 'document',
        action: 'read',
        tenantId: 'other',
        allowCrossTenant: true,
      }),
    ).resolves.toBe(true);
    expect(events.at(-1)?.crossTenant).toBe(true);
  });

  it('should deny cross_tenant_disallowed when only the call-site flag is set', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await expect(
      enforcer.check({
        subject: admin,
        resource: 'document',
        action: 'read',
        allowCrossTenant: true,
      }),
    ).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('cross_tenant_disallowed');
  });

  it('should deny tenant_mismatch when role is crossTenant but allowCrossTenant is missing', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await expect(
      enforcer.check({
        subject: sa,
        resource: 'document',
        action: 'read',
        tenantId: 'other',
      }),
    ).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('tenant_mismatch');
  });

  it('should pass allowCrossTenant when subject has cross-tenant role and same tenant', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await expect(
      enforcer.check({
        subject: sa,
        resource: 'document',
        action: 'read',
        allowCrossTenant: true,
      }),
    ).resolves.toBe(true);
  });

  it('should record condition_threw and fail closed', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    const policyWithThrow = definePolicy({
      roles: { x: {} },
      resources: { y: { actions: ['read'] } },
      conditions: { bad: defineCondition(() => { throw new Error('boom'); }) },
      permissions: { x: { y: { read: { when: 'bad' } } } },
    });
    const e2 = createEnforcer(policyWithThrow, { audit: (event) => events.push(event) });
    const s = createSubject({ id: 'u', roles: ['x'] as const, tenantId: 't1' });
    await expect(e2.check({ subject: s, resource: 'y', action: 'read' })).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('condition_threw');
    expect(events.at(-1)?.cause).toBeInstanceOf(Error);
  });

  it('should emit AuditEvent with policy version', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await enforcer.check({ subject: member, resource: 'document', action: 'read' });
    expect(events.at(-1)?.version).toBe('v1');
    expect(events.at(-1)?.decision).toBe('allow');
    expect(events.at(-1)?.reason).toBe('allowed_by_rule');
  });

  it('should emit grantedBy when matched', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await enforcer.check({ subject: admin, resource: 'document', action: 'read' });
    expect(events.at(-1)?.grantedBy).toBe('member');
  });

  it('should propagate data and tenantId into audit event', async () => {
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    await enforcer.check({
      subject: member,
      resource: 'document',
      action: 'read',
      data: { id: 'doc-1' },
    });
    expect(events.at(-1)?.data).toEqual({ id: 'doc-1' });
    expect(events.at(-1)?.tenantId).toBe('t1');
  });

  it('should allow override of policy conditions via options.conditions', async () => {
    const events: AuditEvent[] = [];
    const policyOpt = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { ok: defineCondition(() => false) },
      permissions: { m: { d: { read: { when: 'ok' } } } },
    });
    const enforcer = createEnforcer(policyOpt, {
      audit: (event) => events.push(event),
      conditions: { ok: defineCondition(() => true) } as never,
    });
    const s = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    await expect(enforcer.check({ subject: s, resource: 'd', action: 'read' })).resolves.toBe(
      true,
    );
  });
});

describe('createEnforcer.checkSync', () => {
  it('should return true synchronously for sync conditions', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    expect(
      enforcer.checkSync({
        subject: member,
        resource: 'document',
        action: 'update',
        data: { ownerId: 'u-member' },
      }),
    ).toBe(true);
  });

  it('should throw ASYNC_CONDITION_IN_SYNC_PATH when async condition is referenced', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { heavy: defineAsyncCondition(async () => true) },
      permissions: { m: { d: { read: { when: 'heavy' } } } },
    });
    const enforcer = createEnforcer(policy);
    const s = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    expect(() => enforcer.checkSync({ subject: s, resource: 'd', action: 'read' })).toThrow(
      PermissionError,
    );
  });

  it('should still emit audit on the sync path without awaiting', () => {
    const policy = buildPolicy();
    const events: AuditEvent[] = [];
    const enforcer = createEnforcer(policy, { audit: (event) => events.push(event) });
    const ok = enforcer.checkSync({ subject: member, resource: 'document', action: 'read' });
    expect(ok).toBe(true);
    expect(events).toHaveLength(1);
  });

  it('should deny when no roles', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    expect(
      enforcer.checkSync({ subject: noRoles, resource: 'document', action: 'read' }),
    ).toBe(false);
  });

  it('should propagate tenant errors synchronously', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const subject = createSubject({ id: 'u', roles: ['member'] as const });
    try {
      enforcer.checkSync({ subject, resource: 'document', action: 'read' });
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      expect((err as PermissionError).code).toBe('TENANT_REQUIRED');
    }
  });

  it('should handle audit hook throw with default log mode', () => {
    const policy = buildPolicy();
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const enforcer = createEnforcer(policy, {
      audit: () => {
        throw new Error('audit boom');
      },
    });
    expect(
      enforcer.checkSync({ subject: member, resource: 'document', action: 'read' }),
    ).toBe(true);
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
  });

  it('should re-throw audit errors when auditFailureMode is throw', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, {
      audit: () => {
        throw new Error('audit boom');
      },
      auditFailureMode: 'throw',
    });
    expect(() =>
      enforcer.checkSync({ subject: member, resource: 'document', action: 'read' }),
    ).toThrow('audit boom');
  });

  it('should fail closed when auditFailureMode is deny and audit throws', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, {
      audit: () => {
        throw new Error('boom');
      },
      auditFailureMode: 'deny',
    });
    expect(
      enforcer.checkSync({ subject: member, resource: 'document', action: 'read' }),
    ).toBe(false);
  });
});

describe('createEnforcer.enforce', () => {
  it('should resolve when allowed', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    await expect(
      enforcer.enforce({ subject: member, resource: 'document', action: 'read' }),
    ).resolves.toBeUndefined();
  });

  it('should throw FORBIDDEN on deny', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    try {
      await enforcer.enforce({ subject: member, resource: 'document', action: 'create' });
      expect.fail('should throw');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      const pe = err as PermissionError;
      expect(pe.code).toBe('FORBIDDEN');
      expect(pe.context?.action).toBe('create');
      expect(pe.context?.resource).toBe('document');
    }
  });
});

describe('createEnforcer.explain', () => {
  it('should return decision metadata for allow', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const decision = await enforcer.explain({
      subject: admin,
      resource: 'document',
      action: 'read',
    });
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe('allowed_by_rule');
    expect(decision.grantedBy).toBe('member');
    expect(typeof decision.durationMs).toBe('number');
  });

  it('should report condition_failed for ABAC denial', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const decision = await enforcer.explain({
      subject: member,
      resource: 'document',
      action: 'update',
      data: { ownerId: 'someone-else' },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('condition_failed');
    expect(decision.conditionName).toBe('isOwner');
  });

  it('should report no_matching_rule when no rule matches', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const decision = await enforcer.explain({
      subject: member,
      resource: 'document',
      action: 'create',
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('no_matching_rule');
  });

  it('should report condition_threw when a condition throws', async () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: {
        bad: defineCondition(() => {
          throw new Error('boom');
        }),
      },
      permissions: { m: { d: { read: { when: 'bad' } } } },
    });
    const enforcer = createEnforcer(policy);
    const s = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const decision = await enforcer.explain({ subject: s, resource: 'd', action: 'read' });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('condition_threw');
    expect(decision.conditionName).toBe('bad');
  });

  it('should report non_boolean_condition_result when condition returns non-boolean', async () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { weird: defineCondition(() => 'maybe' as unknown as boolean) },
      permissions: { m: { d: { read: { when: 'weird' } } } },
    });
    const enforcer = createEnforcer(policy);
    const s = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const decision = await enforcer.explain({ subject: s, resource: 'd', action: 'read' });
    expect(decision.reason).toBe('non_boolean_condition_result');
    expect(decision.conditionName).toBe('weird');
  });
});

describe('createEnforcer.permissionsOf', () => {
  it('should return frozen effective permissions per role-set', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const perms = enforcer.permissionsOf(['admin']);
    expect(Object.isFrozen(perms)).toBe(true);
    expect(perms.document).toBeDefined();
  });

  it('should reuse identical objects across calls (caching)', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const a = enforcer.permissionsOf(['admin']);
    const b = enforcer.permissionsOf(['admin']);
    expect(a).toBe(b);
  });

  it('should treat role order as semantically irrelevant for caching', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, { cacheSize: 4 });
    const a = enforcer.permissionsOf(['admin', 'member']);
    const b = enforcer.permissionsOf(['member', 'admin']);
    expect(a).toBe(b);
  });

  it('should respect LRU cacheSize', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, { cacheSize: 1 });
    const a = enforcer.permissionsOf(['admin']);
    enforcer.permissionsOf(['member']);
    const b = enforcer.permissionsOf(['admin']);
    expect(a).not.toBe(b);
  });

  it('should clamp cacheSize below 1 to 1', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, { cacheSize: 0 });
    expect(() => enforcer.permissionsOf(['admin'])).not.toThrow();
  });
});

describe('createEnforcer.accessibleBy', () => {
  it('should return false for resource with no rules', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const filter = enforcer.accessibleBy({
      subject: noRoles,
      resource: 'document',
      action: 'read',
    });
    expect(filter).toEqual({ kind: 'false' });
  });

  it('should return true for unconditional rule', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const filter = enforcer.accessibleBy({
      subject: member,
      resource: 'document',
      action: 'read',
    });
    expect(filter).toEqual({ kind: 'true' });
  });

  it('should return opaque for unhinted condition', () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy);
    const filter = enforcer.accessibleBy({
      subject: member,
      resource: 'document',
      action: 'update',
    });
    expect(filter).toEqual({ kind: 'opaque', conditionName: 'isOwner' });
  });

  it('should lower a hinted condition into eq AST', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: {
        ownerHint: defineCondition(({ subject, resource }) => {
          const r = resource as { ownerId?: string } | undefined;
          return r?.ownerId === subject.id;
        }, {
          filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }),
        }),
      },
      permissions: { m: { d: { read: { when: 'ownerHint' } } } },
    });
    const enforcer = createEnforcer(policy);
    const s = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const filter = enforcer.accessibleBy({ subject: s, resource: 'd', action: 'read' });
    expect(filter).toEqual({ kind: 'eq', field: 'ownerId', value: 'u' });
  });
});

describe('createEnforcer.withWaitUntil', () => {
  it('should return a new enforcer view with waitUntil bound', async () => {
    const policy = buildPolicy();
    const promises: Array<Promise<unknown>> = [];
    const enforcer = createEnforcer(policy, {
      audit: async () => {
        await Promise.resolve();
      },
    });
    const view = enforcer.withWaitUntil((p) => promises.push(p));
    await view.check({ subject: member, resource: 'document', action: 'read' });
    expect(promises.length).toBeGreaterThan(0);
  });

  it('should fall back to enforcer-level waitUntil when undefined is passed', async () => {
    const policy = buildPolicy();
    const promises: Array<Promise<unknown>> = [];
    const enforcer = createEnforcer(policy, {
      audit: async () => {
        await Promise.resolve();
      },
      waitUntil: (p) => promises.push(p),
    });
    const view = enforcer.withWaitUntil(undefined);
    await view.check({ subject: member, resource: 'document', action: 'read' });
    expect(promises.length).toBeGreaterThan(0);
  });

  it('should keep two views independent (no shared mutable state)', async () => {
    const policy = buildPolicy();
    const a: Array<Promise<unknown>> = [];
    const b: Array<Promise<unknown>> = [];
    const enforcer = createEnforcer(policy, {
      audit: async () => {
        await Promise.resolve();
      },
    });
    const va = enforcer.withWaitUntil((p) => a.push(p));
    const vb = enforcer.withWaitUntil((p) => b.push(p));
    await Promise.all([
      va.check({ subject: member, resource: 'document', action: 'read' }),
      vb.check({ subject: admin, resource: 'document', action: 'read' }),
    ]);
    expect(a.length).toBeGreaterThan(0);
    expect(b.length).toBeGreaterThan(0);
  });
});

describe('createEnforcer audit failure modes', () => {
  let errSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => {
    errSpy.mockRestore();
  });

  it('should default to log mode for sync audit throws', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, {
      audit: () => {
        throw new Error('boom');
      },
    });
    await expect(
      enforcer.check({ subject: member, resource: 'document', action: 'read' }),
    ).resolves.toBe(true);
    expect(errSpy).toHaveBeenCalled();
  });

  it('should log async-rejecting audits in async path', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, {
      audit: () => Promise.reject(new Error('async boom')),
    });
    await expect(
      enforcer.check({ subject: member, resource: 'document', action: 'read' }),
    ).resolves.toBe(true);
    expect(errSpy).toHaveBeenCalled();
  });

  it('should re-throw on auditFailureMode=throw async path', async () => {
    const policy = buildPolicy();
    const enforcer = createEnforcer(policy, {
      audit: () => {
        throw new Error('boom');
      },
      auditFailureMode: 'throw',
    });
    await expect(
      enforcer.check({ subject: member, resource: 'document', action: 'read' }),
    ).rejects.toThrow('boom');
  });

  it('should fail-closed and emit audit_failed on auditFailureMode=deny', async () => {
    const policy = buildPolicy();
    const events: AuditEvent[] = [];
    let throws = true;
    const enforcer = createEnforcer(policy, {
      audit: (event) => {
        if (throws) {
          throws = false;
          throw new Error('boom');
        }
        events.push(event);
      },
      auditFailureMode: 'deny',
    });
    await expect(
      enforcer.check({ subject: member, resource: 'document', action: 'read' }),
    ).resolves.toBe(false);
    expect(events.at(-1)?.reason).toBe('audit_failed');
    expect(events.at(-1)?.decision).toBe('deny');
  });

  it('should forward audit promise to waitUntil when present', async () => {
    const policy = buildPolicy();
    const promises: Array<Promise<unknown>> = [];
    const enforcer = createEnforcer(policy, {
      audit: async () => {
        await Promise.resolve();
      },
      waitUntil: (p) => promises.push(p),
    });
    await enforcer.check({ subject: member, resource: 'document', action: 'read' });
    expect(promises).toHaveLength(1);
  });
});
