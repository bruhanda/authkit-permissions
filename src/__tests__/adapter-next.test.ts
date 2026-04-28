import { describe, expect, it } from 'vitest';
import { nextMiddleware } from '../adapters/next/middleware.js';
import { nextPermissions } from '../adapters/next/route-handler.js';
import { createEnforcer } from '../core/enforcer.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';
import { PermissionError } from '../errors/base.js';
import type { NextRequestLike, NextRouteContext } from '../adapters/next/route-handler.js';

const policy = definePolicy({
  roles: { m: {} },
  resources: { d: { actions: ['read'] } },
  permissions: { m: { d: ['read'] } },
});
const enforcer = createEnforcer(policy);
const allowedSubject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
const deniedSubject = createSubject({ id: 'u', roles: [] as const, tenantId: 't1' });

const fakeReq: NextRequestLike = {
  headers: { get: () => null },
  url: 'https://example.com/x',
};

describe('nextPermissions (route-handler)', () => {
  it('should call the inner handler when allowed', async () => {
    const ctx: NextRouteContext = { params: {} };
    const handler = nextPermissions(
      enforcer,
      {
        getSubject: () => allowedSubject,
        require: () => ({ resource: 'd', action: 'read' }),
      },
      async (_req, _ctx, extras) =>
        new Response(JSON.stringify({ id: extras.subject.id }), { status: 200 }),
    );
    const res = await handler(fakeReq, ctx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.id).toBe('u');
  });

  it('should throw FORBIDDEN on deny so framework can handle it', async () => {
    const ctx: NextRouteContext = { params: {} };
    const handler = nextPermissions(
      enforcer,
      {
        getSubject: () => deniedSubject,
        require: () => ({ resource: 'd', action: 'read' }),
      },
      async () => new Response('ok'),
    );
    await expect(handler(fakeReq, ctx)).rejects.toBeInstanceOf(PermissionError);
  });
});

describe('nextMiddleware', () => {
  it('should return undefined when allowed (continue request)', async () => {
    const middleware = nextMiddleware(enforcer, {
      getSubject: () => allowedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    await expect(middleware(fakeReq)).resolves.toBeUndefined();
  });

  it('should return a 403 Response on FORBIDDEN', async () => {
    const middleware = nextMiddleware(enforcer, {
      getSubject: () => deniedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    const res = (await middleware(fakeReq)) as Response;
    expect(res).toBeInstanceOf(Response);
    expect(res.status).toBe(403);
    expect(await res.text()).toBe('Forbidden');
  });

  it('should re-throw non-FORBIDDEN errors', async () => {
    const middleware = nextMiddleware(enforcer, {
      getSubject: () => {
        throw new Error('auth failure');
      },
      require: () => ({ resource: 'd', action: 'read' }),
    });
    await expect(middleware(fakeReq)).rejects.toThrow('auth failure');
  });

  it('should re-throw non-FORBIDDEN PermissionError codes', async () => {
    const enforceStrict = createEnforcer(policy);
    const middleware = nextMiddleware(enforceStrict, {
      getSubject: () => createSubject({ id: 'u', roles: ['m'] as const }),
      require: () => ({ resource: 'd', action: 'read' }),
    });
    try {
      await middleware(fakeReq);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      expect((err as PermissionError).code).toBe('TENANT_REQUIRED');
    }
  });
});
