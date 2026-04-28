import { describe, expect, it } from 'vitest';
import { fastifyPermissions } from '../adapters/fastify/index.js';
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

const noopReply = {
  code() {
    return noopReply;
  },
  send() {
    return noopReply;
  },
};

describe('fastifyPermissions', () => {
  it('should resolve when allowed', async () => {
    const handler = fastifyPermissions({
      enforcer,
      getSubject: () => allowedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    await expect(handler({}, noopReply)).resolves.toBeUndefined();
  });

  it('should reject with PermissionError on deny', async () => {
    const handler = fastifyPermissions({
      enforcer,
      getSubject: () => deniedSubject,
      require: () => ({ resource: 'd', action: 'read' }),
    });
    await expect(handler({}, noopReply)).rejects.toBeInstanceOf(PermissionError);
  });

  it('should support async hooks', async () => {
    const handler = fastifyPermissions({
      enforcer,
      getSubject: async () => allowedSubject,
      require: async () => ({ resource: 'd', action: 'read' }),
    });
    await expect(handler({}, noopReply)).resolves.toBeUndefined();
  });
});
