# `@authkit/permissions`

[![npm version](https://img.shields.io/npm/v/@authkit/permissions.svg?style=flat-square)](https://www.npmjs.com/package/@authkit/permissions)
[![bundle size](https://img.shields.io/bundlephobia/minzip/@authkit/permissions?style=flat-square&label=gzipped)](https://bundlephobia.com/package/@authkit/permissions)
[![license](https://img.shields.io/npm/l/@authkit/permissions.svg?style=flat-square)](./LICENSE)
[![types](https://img.shields.io/npm/types/@authkit/permissions.svg?style=flat-square)](./src/types/index.ts)

> Lightweight, **zero-dependency**, TypeScript-first RBAC/ABAC for multi-tenant SaaS — under 5 KB gzipped, runs unchanged on Node 20+, Bun, Deno, the browser, Cloudflare Workers, and Vercel Edge.

Authorization is the part of the stack that quietly grows the worst code: ad-hoc `if (user.role === 'admin')` branches, `tenantId` arguments threaded through every function call, "just one more" condition wedged into a CASL ability builder. `@authkit/permissions` keeps the ergonomics of a small declarative policy while filling the gaps that show up in real B2B SaaS — typed inference of every action and resource, a tenant guard that fails closed by default, audit events suitable for SOC 2 logs, and tree-shakeable adapters for the frameworks you already use.

---

## Features

- **Zero runtime dependencies.** Core engine is < 5 KB gzipped, ships ESM only, and runs on every modern JS runtime.
- **Type-safe by construction.** `definePolicy({ ... })` infers role, resource, action, and condition unions. `enforcer.check({ resource: 'pst', action: 'read' })` is a TypeScript error before it is a bug.
- **Multi-tenant as a first-class citizen.** `tenantId` is part of the `Subject` shape and is required at runtime under default `strictTenant: true`. Cross-tenant access requires *both* a role flag and an explicit per-call opt-in (defence in depth).
- **Declarative policy DSL** — roles with `extends`, resources with closed action sets, rules with `when` / `allOf` / `anyOf` / `not`, and an explicit `priority` field instead of relying on object key order.
- **Sync and async conditions** with explicit tagging (`defineCondition` / `defineAsyncCondition`); the engine never speculatively invokes a condition or silently treats a Promise as truthy.
- **`accessibleBy()` lowers conditions into a `FilterAst`** — tiny `eq` / `in` / `and` / `or` / `not` / `opaque` AST that the bundled translators turn into Prisma `where`, Drizzle SQL, or MongoDB query objects.
- **Audit hook on every check** with structured `AuditEvent`s, three failure modes (`log` / `throw` / `deny`), and Workers-safe `waitUntil` plumbing so promises survive the response.
- **Adapters** for Next.js (middleware + Route Handlers), Hono, Express, Fastify, NestJS (Guard + decorator), and tRPC. **UI bindings** for React (`<PermissionProvider>`, `useCan`, `<Can />`) and Vue 3 (plugin, `useCan`, `<Can />`).
- **Fail-fast validation** at `definePolicy()` time: cycles, unknown role/resource/action/condition references, and structural errors throw before the first check.

---

## Quick Start

```ts
import { definePolicy, createEnforcer, createSubject } from '@authkit/permissions';

const policy = definePolicy({
  roles:     { admin: { extends: ['member'] }, member: {} },
  resources: { document: { actions: ['read', 'update', 'delete'] } },
  permissions: {
    admin:  { document: ['*'] },
    member: { document: ['read'] },
  },
});

const enforcer = createEnforcer(policy);
const subject  = createSubject({ id: 'u_1', roles: ['member'], tenantId: 't_1' });

await enforcer.check({ subject, resource: 'document', action: 'read' });   // true
await enforcer.check({ subject, resource: 'document', action: 'delete' }); // false
```

---

## API Reference

The package is split across tree-shakeable subpath exports. Import the surface you actually need.

| Subpath | Purpose |
| --- | --- |
| `@authkit/permissions` | Core: `definePolicy`, `createEnforcer`, `createSubject`, conditions |
| `@authkit/permissions/errors` | `PermissionError`, `ERROR_CODES` |
| `@authkit/permissions/audit` | `composeAudit`, `jsonFormatter`, `tenantHashFormatter`, `withTiming` |
| `@authkit/permissions/builder` | Fluent `createPolicyBuilder()` |
| `@authkit/permissions/adapters/{next,hono,express,fastify,nestjs,trpc}` | HTTP / RPC framework adapters |
| `@authkit/permissions/orm/{prisma,drizzle,mongoose}` | Role loaders + filter translators |
| `@authkit/permissions/react`, `@authkit/permissions/vue` | UI bindings |

### Core

#### `definePolicy(spec)`

```ts
function definePolicy<const P extends PolicySpec>(spec: P & ValidatePolicy<P>): Policy<P>
```

Validates and freezes a policy literal. The returned handle is the source of truth for compile-time inference of roles, resources, actions, and condition names. Throws `PermissionError` on cycles, unknown references, or structural shape errors so configuration mistakes crash at boot.

```ts
const policy = definePolicy({
  version: '2026-04-01',
  roles: {
    superadmin: { extends: ['admin'], crossTenant: true },
    admin:      { extends: ['member'] },
    member:     {},
  },
  resources: {
    document: { actions: ['read', 'update', 'delete'] },
    billing:  { actions: ['view', 'manage'] },
  },
  conditions: {
    isOwner: defineCondition('document', ({ subject, resource }) =>
      resource?.ownerId === subject.id),
  },
  permissions: {
    superadmin: { billing: ['*'] },
    admin:      { document: ['*'], billing: ['view'] },
    member:     { document: { read: true, update: { when: 'isOwner' } } },
  },
});
```

#### `createEnforcer(policy, options?)`

```ts
function createEnforcer<P>(policy: Policy<P>, options?: EnforcerOptions<P>): Enforcer<P>
```

Binds a frozen policy to runtime concerns (audit hook, tenant strictness, cache size) and returns a stateless enforcer instance. Construct once at module load and reuse across requests.

#### `Enforcer<P>` methods

| Method | Description |
| --- | --- |
| `check(args)` | Always-async allow/deny decision. Returns `Promise<boolean>`. |
| `checkSync(args)` | Sync fast path. Throws `ASYNC_CONDITION_IN_SYNC_PATH` if a matching rule references an async / untagged condition. |
| `enforce(args)` | Awaits `check`; throws `PermissionError(FORBIDDEN)` on deny. Convenient at API boundaries. |
| `explain(args)` | Returns a `Decision<P>` with `allowed`, `reason`, `grantedBy`, `conditionName`, `durationMs`. |
| `permissionsOf(roles)` | Deeply-readonly view of compiled `EffectivePermissions` for a role-set. |
| `accessibleBy({ subject, resource, action })` | Lowers the rule into a `FilterAst` for SQL/Mongo `where` clauses. |
| `withWaitUntil(waitUntil)` | Returns a request-bound view that forwards audit promises to `ctx.waitUntil` (Workers / Hono). |
| `policy` | The frozen `Policy<P>` the enforcer was created from. |

```ts
if (await enforcer.check({ subject, resource: 'document', action: 'read' })) { /* ... */ }
await enforcer.enforce({ subject, resource: 'document', action: 'delete', data: doc });

const decision = await enforcer.explain({ subject, resource: 'billing', action: 'manage' });
// { allowed: false, reason: 'no_matching_rule', grantedBy: undefined, ... }
```

#### `createSubject(init)`

```ts
function createSubject<TRole>(init: { id; roles; tenantId?; attrs? }): Subject<TRole>
```

Pure helper that constructs a frozen, properly-typed `Subject`. Useful at the boundary between an authentication library and the enforcer.

```ts
const subject = createSubject({
  id: user.id,
  roles: ['admin', 'member'] as const,
  tenantId: org.id,
});
```

#### `defineCondition(...)` / `defineAsyncCondition(...)`

```ts
function defineCondition<R>(resourceType: R, fn: (args: ConditionArgs<R>) => boolean, hint?): TaggedSyncCondition
function defineCondition<TArgs>(fn: (args: TArgs) => boolean, hint?): TaggedSyncCondition
function defineAsyncCondition(/* same shape, returns Promise<boolean> */): TaggedAsyncCondition
```

Tag a predicate so the engine knows whether to dispatch on the sync or async path. Optionally attach a `ConditionFilterHint` so `accessibleBy()` can lower the condition into SQL.

```ts
declare module '@authkit/permissions' {
  interface ResourceDataMap {
    document: { id: string; ownerId: string; tenantId: string };
  }
}

const isOwner = defineCondition(
  'document',
  ({ subject, resource }) => resource?.ownerId === subject.id,
  { filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }) },
);

const isCollaborator = defineAsyncCondition(
  'document',
  async ({ subject, resource }) => repo.isCollaborator(subject.id, resource?.id),
);
```

#### `composeAudit(...hooks)`

```ts
function composeAudit(...hooks: AuditHook[]): AuditHook
```

Fan an `AuditEvent` out to multiple sinks left-to-right. Errors are aggregated into a single rejection so one slow analytics pipeline cannot mask another.

```ts
import { composeAudit, jsonFormatter, withTiming } from '@authkit/permissions/audit';

const audit = composeAudit(
  withTiming((event) => logger.info(jsonFormatter(event))),
  (event) => Sentry.addBreadcrumb({ category: 'authz', data: event }),
);
```

### Errors

```ts
import { PermissionError, ERROR_CODES, type ErrorCode } from '@authkit/permissions/errors';

try {
  await enforcer.enforce({ subject, resource: 'document', action: 'delete' });
} catch (err) {
  if (err instanceof PermissionError && err.code === ERROR_CODES.FORBIDDEN) {
    return new Response('Forbidden', { status: 403 });
  }
  throw err;
}
```

`ERROR_CODES` covers `INVALID_POLICY`, `ROLE_CYCLE`, `UNKNOWN_ROLE`, `UNKNOWN_RESOURCE`, `UNKNOWN_ACTION`, `UNKNOWN_CONDITION`, `TENANT_REQUIRED`, `TENANT_MISMATCH`, `CONDITION_THREW`, `ASYNC_CONDITION_IN_SYNC_PATH`, `AUDIT_FAILED`, and `FORBIDDEN`.

### Builder

```ts
import { createPolicyBuilder } from '@authkit/permissions/builder';

const policy = createPolicyBuilder()
  .role('admin', { extends: ['member'] })
  .role('member')
  .resource('post', ['read', 'update', 'delete'])
  .permit('admin',  'post', ['*'])
  .permit('member', 'post', ['read'])
  .build();
```

Trades inferred literal types for an imperative, append-only build pipeline. Use `definePolicy` directly when you want full type-narrowed actions/resources at every `enforcer.check` call.

---

## Framework guides

### Next.js (App Router)

```ts
// middleware.ts
import { nextMiddleware } from '@authkit/permissions/adapters/next';
import { enforcer } from '@/lib/authz';
import { sessionFor } from '@/lib/session';

export const middleware = nextMiddleware(enforcer, {
  getSubject: (req) => sessionFor(req),
  require:    () => ({ resource: 'document', action: 'read' }),
});
```

```ts
// app/api/documents/[id]/route.ts
import { nextPermissions } from '@authkit/permissions/adapters/next';

export const GET = nextPermissions(
  enforcer,
  {
    getSubject: (req) => sessionFor(req),
    require:    (_req, { params }) => ({ resource: 'document', action: 'read' }),
  },
  async (_req, { params }, { subject }) => {
    const doc = await loadDocument((await params).id, subject);
    return Response.json(doc);
  },
);
```

The middleware adapter is the only one that catches `FORBIDDEN` itself (Edge middleware runs before the app's error boundary) and returns a 403 `Response`. All other adapters re-throw so your existing error handler decides the response.

### Hono

```ts
import { Hono } from 'hono';
import { honoPermissions } from '@authkit/permissions/adapters/hono';

const app = new Hono();

app.use('/api/*',
  honoPermissions(enforcer, {
    getSubject: (c) => c.var.user,
    require:    () => ({ resource: 'document', action: 'read' }),
    waitUntil:  (c) => c.executionCtx?.waitUntil, // forward to enforcer view
  }),
);
```

### Express

```ts
import { expressPermissions } from '@authkit/permissions/adapters/express';

app.delete('/posts/:id',
  expressPermissions(enforcer, {
    getSubject: (req) => req.user as Subject,
    require:    (req) => ({
      resource: 'post',
      action:   'delete',
      data:     { id: req.params.id },
    }),
  }),
  postsController.delete,
);
```

### Fastify

```ts
import { fastifyPermissions } from '@authkit/permissions/adapters/fastify';

app.delete('/posts/:id', {
  preHandler: fastifyPermissions({
    enforcer,
    getSubject: (req) => req.user as Subject,
    require:    () => ({ resource: 'post', action: 'delete' }),
  }),
}, postsController.delete);
```

### NestJS

```ts
import { Module } from '@nestjs/common';
import { PermissionsModule, PermissionsGuard, Requires } from '@authkit/permissions/adapters/nestjs';

@Module({ imports: [PermissionsModule.forRoot(enforcer)] })
export class AppModule {}

@Injectable()
class AppPermissionsGuard extends PermissionsGuard<typeof policy.spec> {
  constructor(reflector: Reflector) {
    super(reflector, enforcer, (req) => req.user as Subject);
  }
}

@Controller('documents')
export class DocumentsController {
  @Get(':id')
  @Requires({ resource: 'document', action: 'read' })
  read(@Param('id') id: string) { /* ... */ }
}
```

### tRPC

```ts
import { trpcPermissions } from '@authkit/permissions/adapters/trpc';

const requires = trpcPermissions(t, enforcer, {
  getSubject: (ctx) => ctx.user,
});

export const documents = t.router({
  delete: t.procedure
    .use(requires({ resource: 'document', action: 'delete' }))
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => repo.delete(input.id)),
});
```

### React

```tsx
import { PermissionProvider, useCan, Can } from '@authkit/permissions/react';

function App({ subject }) {
  return (
    <PermissionProvider enforcer={enforcer} subject={subject}>
      <DocumentToolbar doc={doc} />
    </PermissionProvider>
  );
}

function DocumentToolbar({ doc }) {
  const canDelete = useCan({ resource: 'document', action: 'delete', data: doc });
  return (
    <>
      <button disabled={!canDelete}>Delete</button>
      <Can resource="document" action="update" data={doc} fallback={<Disabled />}>
        <EditButton />
      </Can>
    </>
  );
}
```

### Vue 3

```ts
import { createApp } from 'vue';
import { createPermissionsPlugin } from '@authkit/permissions/vue';

const app = createApp(App);
app.use(createPermissionsPlugin({ enforcer, subject }));
app.mount('#root');
```

```vue
<script setup>
import { useCan, Can } from '@authkit/permissions/vue';

const canDelete = useCan({ resource: 'document', action: 'delete', data: doc });
</script>

<template>
  <button :disabled="!canDelete">Delete</button>
  <Can resource="document" action="update" :data="doc">
    <EditButton />
    <template #fallback><Disabled /></template>
  </Can>
</template>
```

### ORM filter translators

```ts
import { toPrismaWhere } from '@authkit/permissions/orm/prisma';

const ast = enforcer.accessibleBy({ subject, resource: 'document', action: 'read' });
const where = toPrismaWhere(ast);
const docs = await prisma.document.findMany({ where: { ...where, archived: false } });
```

`toDrizzleWhere` returns a small `DrizzleWhere` description that you map onto `eq` / `inArray` / `and` / `or` / `not` at the call site. `toMongoFilter` returns a plain Mongo query document. Conditions without a filter hint lower to an `opaque` node (treat as match-all + post-fetch check).

The matching `createPrismaRoleAdapter` / `createDrizzleRoleAdapter` / `createMongooseRoleAdapter` helpers load roles for a `(userId, tenantId)` pair into a `Subject`.

---

## Configuration

`createEnforcer(policy, options)` accepts:

| Option | Type | Default | Purpose |
| --- | --- | --- | --- |
| `audit` | `AuditHook` | `undefined` | Called after every check with a structured `AuditEvent`. |
| `auditFailureMode` | `'log' \| 'throw' \| 'deny'` | `'log'` | Behaviour when an audit hook throws/rejects. `'deny'` fails closed and emits a synthetic `audit_failed` event — recommended for SOC 2. |
| `cacheSize` | `number` | `256` | LRU capacity for the effective-permissions table, keyed by sorted role-set. |
| `conditions` | `Partial<InferConditionMap<P>>` | `undefined` | Replace or extend conditions defined in the policy (useful in tests). |
| `strictTenant` | `boolean` | `true` | Throw `TENANT_REQUIRED` when a check is performed without `subject.tenantId`. Disable for single-tenant apps. |
| `waitUntil` | `(p: Promise<unknown>) => void` | `undefined` | Edge-runtime escape hatch for audit promises. Adapters thread `ctx.waitUntil` here. |

`Subject` shape:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | `string` | Stable user id. Used by conditions and audit logs. |
| `roles` | `ReadonlyArray<TRole>` | Roles assigned to the subject for `tenantId`. |
| `tenantId` | `string?` | Required at runtime under `strictTenant: true`. |
| `attrs` | `Readonly<Record<string, unknown>>?` | Optional ABAC attribute bag (department, region, plan, ...). |

`CheckArgs` shape:

| Field | Type | Notes |
| --- | --- | --- |
| `subject` | `Subject<InferRoles<P>>` | Required. |
| `action` | `InferActions<P, R>` | Narrowed by the policy. |
| `resource` | `InferResources<P>` | Narrowed by the policy. |
| `data` | `ResourceData<R>?` | Resource instance for ABAC conditions. |
| `tenantId` | `string?` | Defaults to `subject.tenantId`. |
| `allowCrossTenant` | `boolean?` | Per-call opt-in for cross-tenant access. Requires the role to have `crossTenant: true`. |

---

## TypeScript features

- **Inferred unions everywhere.** `definePolicy` is generic over `const P extends PolicySpec`, so role names, resource keys, action lists, and condition names become literal unions. `enforcer.check({ resource: 'pst', ... })` is a TypeScript error before the call ever runs.
- **Branded `Policy<P>` handle.** `Policy<A>` is structurally incompatible with `Policy<B>` — an enforcer wired to one policy cannot be passed a subject typed for another.
- **`ResourceDataMap` augmentation point.** Declare your resource shapes once; condition bodies and `CheckArgs.data` are narrowed everywhere `data` flows.

  ```ts
  declare module '@authkit/permissions' {
    interface ResourceDataMap {
      document: { id: string; ownerId: string; tenantId: string };
      billing:  { plan: 'free' | 'pro' | 'enterprise' };
    }
  }
  ```

- **`ValidatePolicy<P>` cross-references at the boundary.** `permissions.<role>.<resource>` keys, action lists, and `extends` references are checked against the literal types of `roles` / `resources` / `conditions` at `definePolicy()` time.
- **Type-only inference helpers** (`InferRoles<P>`, `InferResources<P>`, `InferActions<P, R>`, `InferConditions<P>`, `InferConditionMap<P>`) live under `@authkit/permissions` for use in your own helpers.
- **No `any` in the public surface.** Adapters use structural typing instead of importing host frameworks at type level — the package is lint-clean even when peer deps are not installed.

---

## Comparison

Numbers come from the market analysis in `reports/03-rbac-permissions.json` (id `03`, dated 2026-04-27). "Bundle" is the gzipped core import.

| Library | Bundle | Deps | TS-first | Multi-tenant | Edge-safe | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| **`@authkit/permissions`** | **< 5 KB** | **0** | **Yes** | **First-class** | **Yes** | Declarative DSL, `accessibleBy()` filter AST, audit hook, framework adapters. |
| `@casl/ability` | ~12 KB | 0 | Partial | Manual threading | Yes | Mature ecosystem; subject-type model has a learning curve. |
| `casbin` | ~80 KB+ | several | Surface only | No | No | PERM/CONF DSL; powerful but FS-bound. |
| `accesscontrol` | ~9 KB | 0 | `@types/*` only | No | Workarounds | Last release 2022 — abandoned, open security issues. |
| `@rbac/rbac` | ~2 KB | 0 | Minimal | No | Yes | Tiny, but no resource-level rules / no adapters / sparse docs. |
| `role-acl` | ~7 KB | 0 | Yes | No | Yes | JSON-DSL conditions; abandoned 2023. |
| `@openfga/sdk` | n/a (SDK to a server) | several | Yes | Yes | n/a | ReBAC/Zanzibar — needs a separately-deployed PDP. |
| Permit.io / Auth0 FGA / WorkOS FGA | hosted | n/a | Varies | Yes | Yes | Hosted PDPs — vendor lock-in, per-MAU pricing, network latency on every check. |

`@authkit/permissions` exists for the segment those competitors do not serve well: a TypeScript-native B2B SaaS that needs typed, tenant-aware authorization with audit logging, no separate service, and a bundle small enough for Workers / Vercel Edge.

---

## Contributing

Issues and pull requests are welcome at <https://github.com/bruhanda/authkit-permissions>. Before sending a non-trivial change please open an issue to discuss the scope — the package's design constraints (zero deps, < 5 KB, no host-framework imports at type level) are deliberate and not every otherwise-useful feature is in scope (see PLAN.md §10).

Local development:

```sh
npm install
npm run test            # unit tests
npm run test:types      # vitest --typecheck
npm run test:coverage
npm run lint
npm run build
npm run size            # size-limit
```

## License

[MIT](./LICENSE) © Vasyl Bruhanda
