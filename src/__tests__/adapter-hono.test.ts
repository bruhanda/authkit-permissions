import { describe, expect, it, vi } from 'vitest';
import { honoPermissions } from '../adapters/hono/index.js';
import { createEnforcer } from '../core/enforcer.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';
import { PermissionError } from '../errors/base.js';

const policy = definePolicy({
  roles: { m: {} },
  resources: { d: { actions: ['read'] } },
  permissions: { m: { d: ['read'] } },
});

const enforcer = createEnforcer(policy, {
  audit: async () => {
    await Promise.resolve();
  },
});

const allowedSubject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
const deniedSubject = createSubject({ id: 'u', roles: [] as const, tenantId: 't1' });

describe('honoPermissions', () => {
  it('should call next() when allowed', async () => {
    const middleware = honoPermissions(enforcer, {
      getSubject: () => allowedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    const next = vi.fn(async () => undefined);
    await middleware({}, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it('should throw PermissionError on deny', async () => {
    const middleware = honoPermissions(enforcer, {
      getSubject: () => deniedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    const next = vi.fn(async () => undefined);
    await expect(middleware({}, next)).rejects.toBeInstanceOf(PermissionError);
    expect(next).not.toHaveBeenCalled();
  });

  it('should thread executionCtx.waitUntil into the enforcer view', async () => {
    const promises: Array<Promise<unknown>> = [];
    const middleware = honoPermissions(enforcer, {
      getSubject: () => allowedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    await middleware(
      { executionCtx: { waitUntil: (p) => promises.push(p) } },
      async () => undefined,
    );
    expect(promises.length).toBeGreaterThan(0);
  });

  it('should prefer options.waitUntil over executionCtx.waitUntil when provided', async () => {
    const fromOption: Array<Promise<unknown>> = [];
    const fromCtx: Array<Promise<unknown>> = [];
    const middleware = honoPermissions(enforcer, {
      getSubject: () => allowedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
      waitUntil: () => (p) => fromOption.push(p),
    });
    await middleware(
      { executionCtx: { waitUntil: (p) => fromCtx.push(p) } },
      async () => undefined,
    );
    expect(fromOption.length).toBeGreaterThan(0);
    expect(fromCtx.length).toBe(0);
  });
});
