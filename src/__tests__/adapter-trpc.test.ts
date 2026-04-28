import { describe, expect, it, vi } from 'vitest';
import { trpcPermissions } from '../adapters/trpc/index.js';
import { createEnforcer } from '../core/enforcer.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';
import { PermissionError } from '../errors/base.js';
import type { TrpcLike, TrpcMiddlewareFn } from '../adapters/trpc/index.js';

const policy = definePolicy({
  roles: { m: {} },
  resources: { d: { actions: ['read'] } },
  permissions: { m: { d: ['read'] } },
});
const enforcer = createEnforcer(policy);
const allowedSubject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
const deniedSubject = createSubject({ id: 'u', roles: [] as const, tenantId: 't1' });

const buildT = (): {
  t: TrpcLike;
  captured: { fn?: TrpcMiddlewareFn };
} => {
  const captured: { fn?: TrpcMiddlewareFn } = {};
  const t: TrpcLike = {
    middleware: (fn) => {
      captured.fn = fn as TrpcMiddlewareFn;
      return { __middleware: true };
    },
  };
  return { t, captured };
};

describe('trpcPermissions', () => {
  it('should produce a t.middleware that proceeds on allow', async () => {
    const { t, captured } = buildT();
    const requires = trpcPermissions(t, enforcer, {
      getSubject: () => allowedSubject,
    });
    requires({ resource: 'd', action: 'read' });
    const middlewareFn = captured.fn!;
    const next = vi.fn(async () => 'NEXT_RESULT');
    const result = await middlewareFn({ ctx: {}, next });
    expect(next).toHaveBeenCalledOnce();
    expect(result).toBe('NEXT_RESULT');
  });

  it('should throw PermissionError on deny without calling next()', async () => {
    const { t, captured } = buildT();
    const requires = trpcPermissions(t, enforcer, {
      getSubject: () => deniedSubject,
    });
    requires({ resource: 'd', action: 'read' });
    const middlewareFn = captured.fn!;
    const next = vi.fn(async () => undefined);
    await expect(middlewareFn({ ctx: {}, next })).rejects.toBeInstanceOf(PermissionError);
    expect(next).not.toHaveBeenCalled();
  });

  it('should pass ctx into getSubject', async () => {
    const { t, captured } = buildT();
    let received: unknown;
    const requires = trpcPermissions<typeof policy.spec, { user?: string }>(t, enforcer, {
      getSubject: (ctx) => {
        received = ctx;
        return allowedSubject;
      },
    });
    requires({ resource: 'd', action: 'read' });
    const middlewareFn = captured.fn!;
    await middlewareFn({ ctx: { user: 'u' }, next: async () => undefined });
    expect(received).toEqual({ user: 'u' });
  });
});
