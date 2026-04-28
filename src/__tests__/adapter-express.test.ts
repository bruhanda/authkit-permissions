import { describe, expect, it, vi } from 'vitest';
import { expressPermissions } from '../adapters/express/index.js';
import { createEnforcer } from '../core/enforcer.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';
import { PermissionError } from '../errors/base.js';

const policy = definePolicy({
  roles: { m: {} },
  resources: { d: { actions: ['read'] } },
  permissions: { m: { d: ['read'] } },
});

const enforcer = createEnforcer(policy);
const allowedSubject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
const deniedSubject = createSubject({ id: 'u', roles: [] as const, tenantId: 't1' });

const noopRes = {
  status() {
    return noopRes;
  },
  json() {
    return noopRes;
  },
};

describe('expressPermissions', () => {
  it('should call next() when allowed', async () => {
    const middleware = expressPermissions(enforcer, {
      getSubject: () => allowedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    const next = vi.fn();
    await middleware({}, noopRes, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('should call next(err) on deny', async () => {
    const middleware = expressPermissions(enforcer, {
      getSubject: () => deniedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    const next = vi.fn();
    await middleware({}, noopRes, next);
    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0]?.[0];
    expect(err).toBeInstanceOf(PermissionError);
    expect((err as PermissionError).code).toBe('FORBIDDEN');
  });

  it('should propagate errors thrown by getSubject through next()', async () => {
    const middleware = expressPermissions(enforcer, {
      getSubject: () => {
        throw new Error('auth failure');
      },
      require: () => ({ resource: 'd', action: 'read' }),
    });
    const next = vi.fn();
    await middleware({}, noopRes, next);
    expect(next.mock.calls[0]?.[0]).toBeInstanceOf(Error);
  });

  it('should support async getSubject and require', async () => {
    const middleware = expressPermissions(enforcer, {
      getSubject: async () => allowedSubject,
      require: async () => ({ resource: 'd', action: 'read' }),
    });
    const next = vi.fn();
    await middleware({}, noopRes, next);
    expect(next).toHaveBeenCalledWith();
  });
});
