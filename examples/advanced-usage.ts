/**
 * advanced-usage.ts — a realistic multi-tenant document-management scenario.
 *
 * Demonstrates the features that justify reaching for `@authkit/permissions`
 * over a hand-rolled `if (user.role === 'admin')` ladder:
 *
 *   - role inheritance (`superadmin` > `admin` > `member` > `viewer`)
 *   - cross-tenant access gated by **two** flags (defence in depth)
 *   - sync ABAC condition with a filter hint that lowers into a SQL `where`
 *   - async ABAC condition (e.g. "is collaborator?" loaded from a repo)
 *   - structured audit hook (SOC 2-friendly JSON logs)
 *   - `enforcer.accessibleBy()` lowering into Prisma / Mongo `where` clauses
 *
 * Run from the repo root:
 *
 *   npx tsx examples/advanced-usage.ts
 */
import {
  composeAudit,
  createEnforcer,
  createSubject,
  defineAsyncCondition,
  defineCondition,
  definePolicy,
  PermissionError,
  type AuditEvent,
  type ConditionArgs,
} from '@authkit/permissions';
import { jsonFormatter, withTiming } from '@authkit/permissions/audit';
import { toMongoFilter } from '@authkit/permissions/orm/mongoose';
import { toPrismaWhere } from '@authkit/permissions/orm/prisma';

interface DocumentRow {
  readonly id: string;
  readonly ownerId: string;
  readonly tenantId: string;
  readonly archived: boolean;
}

declare module '@authkit/permissions' {
  interface ResourceDataMap {
    document: DocumentRow;
    billing:  { readonly tenantId: string; readonly plan: 'free' | 'pro' | 'enterprise' };
  }
}

const collaborators = new Map<string, ReadonlySet<string>>([
  ['doc_alpha', new Set(['u_carol'])],
  ['doc_beta',  new Set([])],
]);

const isOwner = defineCondition<ConditionArgs>(
  ({ subject, resource }) =>
    (resource as DocumentRow | undefined)?.ownerId === subject.id,
  { filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }) },
);

const notArchived = defineCondition<ConditionArgs>(
  ({ resource }) => (resource as DocumentRow | undefined)?.archived !== true,
  { filter: () => ({ kind: 'eq', field: 'archived', value: false }) },
);

const isCollaborator = defineAsyncCondition<ConditionArgs>(async ({ subject, resource }) => {
  const doc = resource as DocumentRow | undefined;
  if (doc === undefined) return false;
  const set = collaborators.get(doc.id);
  return set?.has(subject.id) === true;
});

const policy = definePolicy({
  version: '2026-04-28',
  roles: {
    superadmin: { extends: ['admin'], crossTenant: true },
    admin:      { extends: ['member'] },
    member:     { extends: ['viewer'] },
    viewer:     {},
  },
  resources: {
    document: { actions: ['read', 'update', 'delete', 'archive'] as const },
    billing:  { actions: ['view', 'manage'] as const },
  },
  conditions: {
    isOwner,
    notArchived,
    isCollaborator,
  },
  permissions: {
    superadmin: { billing: ['*'], document: ['*'] },
    admin:      { document: ['*'], billing: ['view'] },
    member: {
      document: {
        read:   true,
        update: { allOf: [{ anyOf: ['isOwner', 'isCollaborator'] }, 'notArchived'] },
        delete: { rule: { when: 'isOwner' }, priority: 10 },
      },
    },
    viewer: { document: ['read'] },
  },
});

const auditEvents: AuditEvent[] = [];

const enforcer = createEnforcer(policy, {
  audit: composeAudit(
    withTiming((event) => {
      auditEvents.push(event);
      console.log('[audit]', jsonFormatter(event));
    }),
  ),
  auditFailureMode: 'log',
  cacheSize: 64,
});

const alice = createSubject({
  id: 'u_alice',
  roles: ['member'] as const,
  tenantId: 't_acme',
});

const bob = createSubject({
  id: 'u_bob',
  roles: ['admin'] as const,
  tenantId: 't_acme',
});

const carol = createSubject({
  id: 'u_carol',
  roles: ['member'] as const,
  tenantId: 't_acme',
});

const root = createSubject({
  id: 'u_root',
  roles: ['superadmin'] as const,
  tenantId: 't_authkit',
});

const docAlpha = {
  id: 'doc_alpha',
  ownerId: alice.id,
  tenantId: 't_acme',
  archived: false,
} as const;

const docBeta = {
  id: 'doc_beta',
  ownerId: bob.id,
  tenantId: 't_acme',
  archived: true,
} as const;

async function main(): Promise<void> {
  console.log('=== ABAC: ownership + freshness ===');
  console.log(
    'alice can update her own non-archived doc:',
    await enforcer.check({
      subject:  alice,
      resource: 'document',
      action:   'update',
      data:     docAlpha,
    }),
  );

  console.log(
    'alice can update an archived doc she owns:',
    await enforcer.check({
      subject:  alice,
      resource: 'document',
      action:   'update',
      data:     { ...docAlpha, archived: true },
    }),
  );

  console.log('\n=== async condition (collaborator lookup) ===');
  console.log(
    'carol (collaborator) can update alpha:',
    await enforcer.check({
      subject:  carol,
      resource: 'document',
      action:   'update',
      data:     docAlpha,
    }),
  );

  console.log('\n=== explain() surfaces grantedBy + condition ===');
  const decision = await enforcer.explain({
    subject:  alice,
    resource: 'document',
    action:   'delete',
    data:     docAlpha,
  });
  console.log(decision);

  console.log('\n=== cross-tenant requires role flag + per-call opt-in ===');
  try {
    // bob is admin in t_acme but does NOT have crossTenant — this denies.
    await enforcer.enforce({
      subject:           bob,
      resource:          'document',
      action:            'read',
      tenantId:          't_other',
      allowCrossTenant:  true,
    });
  } catch (err) {
    if (err instanceof PermissionError) {
      console.log('bob denied cross-tenant:', err.code);
    } else throw err;
  }

  // root is superadmin (crossTenant: true) AND passes `allowCrossTenant`.
  console.log(
    'root (superadmin) reads across tenants:',
    await enforcer.check({
      subject:           root,
      resource:          'document',
      action:            'read',
      tenantId:          't_acme',
      allowCrossTenant:  true,
    }),
  );

  console.log('\n=== accessibleBy() → SQL/Mongo where clauses ===');
  const ast = enforcer.accessibleBy({
    subject:  alice,
    resource: 'document',
    action:   'delete',
  });
  console.log('FilterAst:', JSON.stringify(ast));
  console.log('toPrismaWhere:', JSON.stringify(toPrismaWhere(ast)));
  console.log('toMongoFilter:', JSON.stringify(toMongoFilter(ast)));

  console.log('\n=== audit trail captured ===');
  console.log(`${auditEvents.length} events recorded for SOC 2 logs.`);
}

void main();
