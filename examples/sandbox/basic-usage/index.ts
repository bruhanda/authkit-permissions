/**
 * basic-usage — minimal core functionality of `@authkit/permissions`.
 *
 *   1. `definePolicy()`   — declarative roles, resources, permissions.
 *   2. `createEnforcer()` — bind the policy to runtime concerns.
 *   3. `createSubject()`  — frozen, typed subject helper.
 *   4. `enforcer.check / enforce / explain` — three call shapes.
 */
import {
  createEnforcer,
  createSubject,
  definePolicy,
  ERROR_CODES,
  PermissionError,
} from '@authkit/permissions';

const policy = definePolicy({
  version: '2026-04-28',
  roles: {
    admin:  { extends: ['member'] },
    member: {},
  },
  resources: {
    document: { actions: ['read', 'update', 'delete'] as const },
  },
  permissions: {
    admin:  { document: ['*'] },
    member: { document: ['read'] },
  },
});

const enforcer = createEnforcer(policy, {
  // Tiny demo: skip the multi-tenant guard so examples don't need a tenantId.
  // Real apps keep `strictTenant: true` (the default) — see advanced-usage.
  strictTenant: false,
});

const alice = createSubject({ id: 'u_alice', roles: ['member'] as const });
const bob   = createSubject({ id: 'u_bob',   roles: ['admin']  as const });

async function main(): Promise<void> {
  console.log('— check() returns a boolean —');
  console.log(
    'alice can read document:',
    await enforcer.check({ subject: alice, resource: 'document', action: 'read' }),
  );
  console.log(
    'alice can delete document:',
    await enforcer.check({ subject: alice, resource: 'document', action: 'delete' }),
  );
  console.log(
    'bob can delete document:',
    await enforcer.check({ subject: bob, resource: 'document', action: 'delete' }),
  );

  console.log('\n— explain() shows why —');
  console.log(
    await enforcer.explain({ subject: alice, resource: 'document', action: 'delete' }),
  );

  console.log('\n— enforce() throws on deny —');
  try {
    await enforcer.enforce({ subject: alice, resource: 'document', action: 'delete' });
  } catch (err) {
    if (err instanceof PermissionError && err.code === ERROR_CODES.FORBIDDEN) {
      console.log('caught FORBIDDEN:', err.message);
    } else throw err;
  }
}

void main();
