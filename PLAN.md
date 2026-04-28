# `@authkit/permissions` — Architecture Plan

> Lightweight, **zero-dependency**, TypeScript-first RBAC/ABAC with a multi-tenant
> context as a first-class citizen. Targets **<5KB gzipped** for the core engine
> and runs unmodified in **Node 20+, Bun, Deno, Browser, Cloudflare Workers and
> Vercel Edge** (ESM-only — every supported runtime ships native ESM in 2026).
> Optional, tree-shakeable adapters for **Next.js, Hono, Express, Fastify,
> NestJS, tRPC, React and Vue**.

The library is positioned to fill the vacuum left by the abandonment of
`accesscontrol` (last release 2022) and to compete on **DX + bundle-size**
against `@casl/ability` (~12 KB, no first-class tenant) and `casbin` (~80 KB,
PERM/CONF DSL). Source of truth for the market problem statement is
`reports/03-rbac-permissions.json` (id `03`, dated 2026-04-27).

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Public API Design](#2-public-api-design)
3. [Internal Architecture](#3-internal-architecture)
4. [Type System](#4-type-system)
5. [Error Handling Strategy](#5-error-handling-strategy)
6. [Bundle & Tree-shaking Plan](#6-bundle--tree-shaking-plan)
7. [Dependencies](#7-dependencies)
8. [Configuration](#8-configuration)
9. [Edge Cases](#9-edge-cases)
10. [Out of Scope (1.0)](#10-out-of-scope-10)

---

## 1. Project Structure

Every file in `src/` is single-purpose; no file imports from `dist/`, no file
imports from a sibling `index.ts` re-export (we re-export only at package
boundaries to keep the dep graph acyclic and tree-shakeable).

```
authkit-permissions/
├── PLAN.md                          # this document
├── README.md                        # user-facing docs (5-min getting started)
├── LICENSE                          # MIT
├── package.json                     # see §8
├── tsconfig.json                    # strict, ES2022, NodeNext, declaration
├── tsconfig.build.json              # build-only overrides (no tests)
├── tsup.config.ts                   # multi-entry esm+cjs+dts bundler
├── vitest.config.ts                 # workspace incl. workers / browser pools
├── biome.json                       # lint + format (replaces eslint+prettier)
├── .gitignore                       # see §8
├── .changeset/                      # changesets release tracking
│   └── config.json
├── .github/
│   └── workflows/
│       ├── ci.yml                   # test + typecheck + size-limit + attw
│       └── release.yml              # changesets publish on main
│
├── src/
│   ├── index.ts                     # single public entrypoint for core
│   │                                # re-exports definePolicy, createEnforcer,
│   │                                # createSubject, type helpers, error class
│   │
│   ├── core/
│   │   ├── policy.ts                # definePolicy() — pure data validator
│   │   │                            # - normalises role graph
│   │   │                            # - freezes policy object (Object.freeze)
│   │   │                            # - returns typed Policy<P> handle
│   │   ├── enforcer.ts              # createEnforcer() — stateless check engine
│   │   │                            # - resolves effective permissions per role
│   │   │                            # - evaluates conditions (always-async by
│   │   │                            #   default; opt-in sync via
│   │   │                            #   defineCondition())
│   │   │                            # - emits audit events
│   │   ├── role-graph.ts            # topological order + cycle detection
│   │   │                            # - compiled once at definePolicy() time
│   │   │                            # - precomputes transitive role closure
│   │   ├── matcher.ts               # wildcard + literal action/resource match
│   │   │                            # - "*", "post:*", "*:read", "post:read"
│   │   │                            # - segment-aware glob, no regex (perf)
│   │   ├── conditions.ts            # condition registry + evaluator
│   │   │                            # - defineCondition() / defineAsyncCondition()
│   │   │                            #   tag at compile-time so the engine never
│   │   │                            #   speculatively invokes a condition
│   │   ├── effective.ts             # resolveEffectivePermissions(roles[])
│   │   │                            # - LRU memoised by sorted-role-tuple string
│   │   │                            #   (no hash — exact-match key)
│   │   ├── accessible.ts            # accessibleBy(enforcer, subject, resource)
│   │   │                            # - returns normalised filter AST consumed by
│   │   │                            #   orm/{prisma,drizzle,mongoose}
│   │   ├── memo.ts                  # tiny LRU (≈30 LOC) — used by effective.ts
│   │   └── freeze.ts                # deepFreeze helper for defensive copies
│   │
│   ├── types/
│   │   ├── index.ts                 # type-only public surface
│   │   ├── policy.ts                # Policy, RoleDef, ResourceDef, RuleDef
│   │   ├── subject.ts               # Subject<TRole, TTenant>
│   │   ├── context.ts               # CheckContext, ResourceData
│   │   ├── result.ts                # CheckResult, DenyReason, Decision
│   │   ├── condition.ts             # ConditionFn + AsyncConditionFn
│   │   ├── audit.ts                 # AuditEvent, AuditHook
│   │   └── inference.ts             # type-level helpers:
│   │                                # InferActions<P, R>, InferResources<P>,
│   │                                # InferRoles<P>, InferConditions<P>
│   │
│   ├── errors/
│   │   ├── index.ts                 # subpath barrel: error class + codes
│   │   ├── base.ts                  # PermissionError extends Error
│   │   └── codes.ts                 # ERROR_CODES const + type
│   │
│   ├── audit/
│   │   ├── index.ts                 # audit subpath barrel
│   │   ├── hook.ts                  # AuditHook type + composeAudit(...hooks)
│   │   ├── formatter.ts             # default structured JSON formatter
│   │   └── timing.ts                # opt-in performance.now() timing wrapper
│   │
│   ├── builder/
│   │   ├── index.ts                 # createPolicyBuilder() — fluent DSL
│   │   └── fluent.ts                # internal builder state machine
│   │
│   ├── utils/
│   │   ├── env.ts                   # isDev() — single portable runtime probe
│   │   │                            # `typeof process !== 'undefined' &&
│   │   │                            #  process.env?.NODE_ENV !== 'production'`
│   │   │                            # banned via Biome rule from being inlined
│   │   │                            # anywhere else (Workers/Deno safety)
│   │   ├── invariant.ts             # invariant(cond, msg, code) → throws PermissionError
│   │   ├── is-record.ts             # narrow `unknown` → Record<string, unknown>
│   │   └── set-ops.ts               # union/intersect for tiny role sets
│   │
│   ├── adapters/
│   │   ├── next/
│   │   │   ├── index.ts             # nextPermissions(handler), nextMiddleware()
│   │   │   └── route-handler.ts     # type-narrowed wrappers for App Router
│   │   ├── hono/
│   │   │   └── index.ts             # honoPermissions(enforcer, getSubject)
│   │   ├── express/
│   │   │   └── index.ts             # expressPermissions(...)
│   │   ├── fastify/
│   │   │   └── index.ts             # fastifyPermissions(...) — Fastify plugin
│   │   ├── nestjs/
│   │   │   ├── index.ts             # PermissionsGuard, @Requires() decorator
│   │   │   └── module.ts            # PermissionsModule.forRoot()
│   │   └── trpc/
│   │       └── index.ts             # trpcPermissions<TRPC>()
│   │
│   ├── orm/
│   │   ├── prisma/
│   │   │   ├── index.ts             # createPrismaRoleAdapter(prisma, schema) +
│   │   │   │                        # toPrismaWhere(filter) — translates the
│   │   │   │                        # filter AST from accessibleBy() into a
│   │   │   │                        # `Prisma.<Model>WhereInput` shape
│   │   │   └── filter.ts            # AST → Prisma where translator
│   │   ├── drizzle/
│   │   │   ├── index.ts             # createDrizzleRoleAdapter + toDrizzleWhere
│   │   │   └── filter.ts            # AST → Drizzle SQL fragment
│   │   └── mongoose/
│   │       ├── index.ts             # createMongooseRoleAdapter + toMongoFilter
│   │       └── filter.ts            # AST → Mongo query
│   │
│   ├── react/
│   │   ├── index.ts                 # public surface (useCan, <Can/>, provider)
│   │   ├── context.tsx              # PermissionContext (React.createContext)
│   │   ├── provider.tsx             # <PermissionProvider enforcer subject />
│   │   ├── use-can.ts               # useCan(action, resource, data?)
│   │   └── can.tsx                  # <Can/> component with `fallback` slot
│   │
│   └── vue/
│       ├── index.ts                 # public surface
│       ├── plugin.ts                # createPermissionsPlugin() Vue 3 plugin
│       ├── use-can.ts               # useCan() composable
│       └── can.ts                   # <Can/> SFC (defineComponent)
│
├── test/
│   ├── core/
│   │   ├── policy.test.ts           # definePolicy validation, freeze, cycles
│   │   ├── enforcer.test.ts         # check() matrix
│   │   ├── role-graph.test.ts       # cycle detection, deep inheritance
│   │   ├── matcher.test.ts          # wildcards
│   │   ├── conditions.test.ts       # sync + async + missing condition
│   │   └── multi-tenant.test.ts     # tenant-leakage regression matrix
│   ├── types/
│   │   └── inference.test-d.ts      # vitest --typecheck
│   ├── adapters/
│   │   ├── hono.test.ts
│   │   ├── express.test.ts
│   │   ├── fastify.test.ts
│   │   ├── trpc.test.ts
│   │   └── next.test.ts
│   ├── react/
│   │   ├── use-can.test.tsx
│   │   └── can.test.tsx             # @testing-library/react
│   ├── vue/
│   │   └── use-can.test.ts          # @vue/test-utils
│   ├── runtime/
│   │   ├── workers.test.ts          # @cloudflare/vitest-pool-workers
│   │   └── edge.test.ts             # globalThis.process undefined check
│   └── bench/
│       └── enforcer.bench.ts        # vitest bench
│
└── examples/                        # not published — referenced from README
    ├── nextjs-app-router/
    ├── hono-edge/
    ├── trpc-multi-tenant/
    └── nestjs-guard/
```

### Why split `core` into 8 small files?

Each file is < 150 LOC and has a single responsibility. Tree-shakers (Rollup,
esbuild) can drop any unused leaf. The same module graph is bundled by `tsup`
with `treeshake: 'recommended'` so a consumer that only calls `definePolicy`
will not pull `enforcer.ts`, `effective.ts` or `memo.ts`.

---

## 2. Public API Design

The library has **one mental model** the user must learn:

> *Policy is a value, not a config file.*

A policy is a frozen TypeScript object produced by `definePolicy(...)`. From
that single value we **infer** every legal `(role, resource, action)` triple at
the type level. The user then creates an `Enforcer` (a stateless functional
object) and calls `enforcer.check(...)` per request. There is no global state,
no singleton, no mutation API, no ".conf" file.

### 2.1 `definePolicy` — the one-call factory

```ts
/**
 * Define a frozen, fully-typed RBAC/ABAC policy.
 *
 * The returned `Policy` is the source of truth for *all* compile-time type
 * inference (roles, resources, actions, conditions). It is also a frozen
 * runtime value — mutations throw in strict mode and are silently discarded
 * in sloppy mode.
 *
 * @typeParam P - inferred shape of the policy literal. Never specify manually.
 * @param spec - declarative policy literal (see {@link PolicySpec}).
 * @returns frozen, validated {@link Policy} handle.
 * @throws {@link PermissionError} with code `INVALID_POLICY` when the spec is
 *   structurally invalid (e.g. role cycle, unknown resource in `permissions`,
 *   missing condition referenced from a rule).
 *
 * @example
 *   const policy = definePolicy({
 *     roles: {
 *       owner:  { extends: ['admin'] },
 *       admin:  { extends: ['member'] },
 *       member: { extends: ['viewer'] },
 *       viewer: {},
 *     },
 *     resources: {
 *       project:  { actions: ['create', 'read', 'update', 'delete', 'invite'] },
 *       document: { actions: ['create', 'read', 'update', 'delete', 'comment'] },
 *     },
 *     conditions: {
 *       isOwner:    ({ subject, resource }) => resource?.ownerId === subject.id,
 *       sameTenant: ({ subject, resource }) => resource?.tenantId === subject.tenantId,
 *     },
 *     permissions: {
 *       viewer: {
 *         project:  ['read'],
 *         document: ['read', 'comment'],
 *       },
 *       member: {
 *         document: {
 *           create: true,
 *           update: { when: 'isOwner' },
 *           delete: { when: ['isOwner', 'sameTenant'] }, // AND
 *         },
 *       },
 *       admin: {
 *         project:  ['create', 'update', 'invite'],
 *         document: ['delete'],
 *       },
 *       owner: {
 *         project:  ['*'], // all actions defined for `project`
 *         document: ['*'],
 *       },
 *     },
 *   });
 */
export function definePolicy<const P extends PolicySpec>(spec: P): Policy<P>;
```

**Key DX choices**:

- `const` type parameter (TS 5.0+) preserves the literal types of every
  string — no `as const` cargo from the user.
- Inheritance is declared via `extends: string[]`, **not** by the order keys
  appear in the object. This makes the policy diffable and re-orderable.
- Permissions can be expressed in three escalating shapes:
  - **string array** — implicit `true` (`['read', 'update']`)
  - **wildcard** — `['*']` expands to every action declared for that resource
  - **rule object** — `{ create: true, update: { when: 'isOwner' } }`
- Conditions are referenced **by name** (string) so the policy stays
  serialisable (audit-friendly) and conditions can be injected/swapped at
  enforcer-creation time for testing.

### 2.2 `createEnforcer` — the per-request decision engine

```ts
/**
 * Bind a policy to runtime concerns (audit hook, condition overrides, role
 * resolver). The returned enforcer is **stateless** apart from a private
 * memoisation cache for the effective-permissions table.
 *
 * Safe to construct once at module load and reuse across requests in any
 * runtime (Node, Edge, Workers).
 *
 * @example
 *   export const enforcer = createEnforcer(policy, {
 *     audit: (event) => logger.info({ msg: 'authz', ...event }),
 *   });
 */
export function createEnforcer<P extends PolicySpec>(
  policy: Policy<P>,
  options?: EnforcerOptions<P>,
): Enforcer<P>;

export interface EnforcerOptions<P extends PolicySpec> {
  /** Replace or extend conditions defined in the policy (e.g. for tests). */
  conditions?: Partial<InferConditionMap<P>>;
  /** Audit hook called after every check. */
  audit?: AuditHook;
  /** Cache size for the effective-permissions LRU (default 256). */
  cacheSize?: number;
  /**
   * If `true`, throws {@link PermissionError} `TENANT_REQUIRED` when a check
   * is performed without a `tenantId` on the subject AND the resource. Default
   * `true` — the whole point of this library is that tenant-leakage is a
   * compile-time and run-time error.
   */
  strictTenant?: boolean;
  /**
   * Behaviour when an `audit` hook throws or rejects:
   *
   *   - `'log'`   (default) — error is captured to `console.error`, decision
   *                           is returned unchanged. UI-friendly default.
   *   - `'throw'`             — re-throws after the decision so a global
   *                             error handler can surface the broken pipeline.
   *   - `'deny'`              — fails closed: the check returns `false` and
   *                             emits a synthetic `AUDIT_FAILED` audit event.
   *                             Recommended for SOC2 customers who treat the
   *                             audit log as a compliance artifact.
   */
  auditFailureMode?: 'log' | 'throw' | 'deny';
  /**
   * Edge-runtime escape hatch. When provided, the enforcer hands any
   * fire-and-forget audit promise to `waitUntil(p)` instead of relying on
   * `queueMicrotask` (which is not guaranteed to run after a Workers
   * `Response` is returned). Adapters wire this from `ctx.waitUntil`.
   */
  waitUntil?: (p: Promise<unknown>) => void;
}
```

The `Enforcer<P>` instance exposes a small, intention-revealing surface:

```ts
export interface Enforcer<P extends PolicySpec> {
  /**
   * Allow / deny decision with full type-safety on action and resource.
   * **Always returns a Promise** — the previous `boolean | Promise<boolean>`
   * union was unsafe (a forgotten `await` resolves to a truthy object and
   * silently grants access). Tests show no measurable hot-path penalty;
   * the LRU + frozen rule table dwarfs one Promise allocation per call.
   */
  check<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<boolean>;

  /**
   * Synchronous fast-path. Returns a `boolean` only when every condition
   * matched by the rule was registered via `defineCondition()` (sync-tagged).
   * If any matching condition was registered via `defineAsyncCondition()`
   * (or is untagged — treated as async), throws
   * `PermissionError(ASYNC_CONDITION_IN_SYNC_PATH)` so the caller surfaces
   * the bug at call time instead of via a silent allow / deny.
   */
  checkSync<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): boolean;

  /**
   * Same as {@link check} but throws {@link PermissionError} (`FORBIDDEN`)
   * on deny. Useful at API boundaries to short-circuit handlers without
   * branching. Renamed from `authorize()` because "authorize" in security
   * parlance means *issue a token*; this method *asserts* a permission.
   */
  enforce<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<void>;

  /**
   * Inspectable explain — returns the decision plus the rule that produced it,
   * the role it came from, and the conditions evaluated. Designed for audit
   * logs and test assertions, not for hot paths.
   */
  explain<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<Decision<P, R, A>>;

  /**
   * Returns a deeply-readonly view of the effective-permission set.
   * No defensive deep-clone — `Readonly<...>` plus a frozen source is
   * sufficient and avoids bytes the deep-clone path would burn on every
   * inspection call.
   */
  permissionsOf(
    roles: ReadonlyArray<InferRoles<P>>,
  ): Readonly<EffectivePermissions<P>>;

  /** Reference back to the policy (frozen). */
  readonly policy: Policy<P>;
}
```

`CheckArgs` collects every input the engine needs:

```ts
export interface CheckArgs<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> {
  /** Caller — must always carry roles and (in strictTenant mode) tenantId. */
  subject: Subject<InferRoles<P>>;
  /** Action being attempted on `resource`. */
  action: A;
  /** Resource type — string literal must match a declared resource. */
  resource: R;
  /**
   * Optional resource instance for ABAC conditions (ownership, tenancy).
   * Narrows automatically when the consumer augments `ResourceDataMap`
   * (see §4.4) — passing the wrong shape becomes a TS error at the call
   * site, not just inside the condition body.
   */
  data?: R extends keyof ResourceDataMap
    ? ResourceDataMap[R]
    : Record<string, unknown>;
  /**
   * Tenant scope of the check. Defaults to `subject.tenantId`. Passing a
   * different value triggers `TENANT_MISMATCH` unless **both** of the
   * following hold (defence in depth):
   *
   *   1. The subject carries a role with `crossTenant: true` in the policy.
   *   2. This call explicitly opts in via `allowCrossTenant: true`.
   *
   * Cross-tenant access is something humans should write at the call site,
   * not configure in policy and forget. Always audit-flagged.
   */
  tenantId?: string;
  /** Per-call opt-in for cross-tenant access. See `tenantId` above. */
  allowCrossTenant?: boolean;
}
```

### 2.3 Top-level conveniences

```ts
/** Construct a properly-typed Subject. Pure helper — no state. */
export function createSubject<TRole extends string>(
  init: { id: string; roles: ReadonlyArray<TRole>; tenantId?: string; attrs?: Record<string, unknown> },
): Subject<TRole>;

/** Compose multiple audit hooks into one (left-to-right). */
export function composeAudit(...hooks: AuditHook[]): AuditHook;

/** Re-exports from sub-barrels for convenience (tree-shakeable). */
export { PermissionError, ERROR_CODES } from './errors';
export type * from './types';
```

### 2.4 Adapters — minimal, framework-idiomatic

Every adapter is **thin**: it converts the framework's request/context to a
`Subject`, calls `enforcer.enforce(...)`, and lets the framework handle the
thrown `PermissionError` via its own error pipeline.

**Naming convention.** The middleware factory in every server adapter is
`<framework>Permissions(enforcer, options)`. Per-route helpers use the
`require*` / `protect*` family. The two patterns are intentionally distinct
so that import autocomplete tells the user which level they're at —
"middleware that runs on every request" vs. "wrapper around a single route
handler". Workers/Vercel adapters also accept a `waitUntil` option that
forwards to the enforcer so audit promises survive past the response.

#### Hono

```ts
import { honoPermissions } from '@authkit/permissions/adapters/hono';

app.use(
  '/api/*',
  honoPermissions(enforcer, {
    getSubject: (c) => c.var.user,                  // your auth result
    require:    (c) => ({ resource: 'document', action: 'read' }),
    waitUntil:  (c) => c.executionCtx.waitUntil,    // Workers-safe audit
  }),
);
```

#### Next.js (App Router)

```ts
// app/api/documents/[id]/route.ts
import { nextPermissions } from '@authkit/permissions/adapters/next';

export const GET = nextPermissions(
  enforcer,
  { resource: 'document', action: 'read' },
  async (req, { params, subject }) => Response.json(await load(params.id)),
);
```

#### Express / Fastify

```ts
import { expressPermissions } from '@authkit/permissions/adapters/express';
import { fastifyPermissions } from '@authkit/permissions/adapters/fastify';

app.use(expressPermissions(enforcer, { getSubject: (req) => req.user }));
fastify.register(fastifyPermissions, { enforcer, getSubject: (req) => req.user });
```

#### tRPC

```ts
import { trpcPermissions } from '@authkit/permissions/adapters/trpc';

export const requires = trpcPermissions(t, enforcer);

export const documentsRouter = t.router({
  delete: t.procedure
    .use(requires({ resource: 'document', action: 'delete' }))
    .input(z.object({ id: z.string() }))
    .mutation(({ ctx, input }) => repo.delete(input.id)),
});
```

#### NestJS

```ts
@Controller('documents')
@UseGuards(PermissionsGuard)
export class DocumentsController {
  @Get(':id')
  @Requires({ resource: 'document', action: 'read' })
  read(@Param('id') id: string) { /* … */ }
}
```

#### React

```tsx
import { PermissionProvider, useCan, Can } from '@authkit/permissions/react';

<PermissionProvider enforcer={enforcer} subject={subject}>
  <Can action="delete" resource="document" data={doc} fallback={<Disabled />}>
    <DeleteButton />
  </Can>
</PermissionProvider>
```

```ts
// useCan takes the same object shape as enforcer.check — never positional.
// Reviewer flagged the (action, resource) vs (resource, action) confusion;
// keeping a single shape across server + client kills that whole bug class.
const allowed = useCan({ action: 'update', resource: 'document', data: doc });
```

### 2.5 ORM helpers — `loadSubject` + `accessibleBy`

Two pure-function helpers per ORM, both consumed by the same adapter module.

**1. `loadSubject(...)`** — load `roles` and `tenantId` for a user from a
typical `memberships` table.

```ts
import { createPrismaRoleAdapter } from '@authkit/permissions/orm/prisma';

const roleAdapter = createPrismaRoleAdapter(prisma, {
  membershipModel: 'membership',
  userField:       'userId',
  tenantField:     'tenantId',
  roleField:       'role',
});

const subject = await roleAdapter.loadSubject({ userId, tenantId });
```

**2. `accessibleBy(enforcer, subject, resource, action)`** — push authorization
*down into the database query*. Returns a normalised filter AST that adapter
helpers translate to native query primitives. This closes the row-level
filtering gap — without it, the library is a tier behind CASL on the most
common SaaS scenario ("user only sees their own resources") and SOC2 row-level
enforcement.

```ts
import { accessibleBy } from '@authkit/permissions';
import { toPrismaWhere } from '@authkit/permissions/orm/prisma';

// Every doc the subject can `read` — joined with whatever filter the caller
// would have written by hand. tenantId / ownerId / etc. fall out of the
// policy automatically.
const filter = accessibleBy(enforcer, { subject, resource: 'document', action: 'read' });
const docs = await prisma.document.findMany({
  where: { ...toPrismaWhere(filter), archived: false },
});
```

The filter AST is intentionally tiny (`{ field, op, value }` plus
`and / or / not` combinators) so each adapter is < 60 LOC. The same AST flows
through `toDrizzleWhere` and `toMongoFilter` — application code stays
ORM-agnostic. Conditions that cannot be expressed as a filter (e.g. arbitrary
`isOwner` lambdas with no field hint) degrade safely to a post-fetch check;
this is documented per condition in the README and is the reason
`accessibleBy` lives outside the always-loaded core (no extra bytes for users
who only need `enforcer.check`).

---

## 3. Internal Architecture

### 3.1 Module dependency graph

```
                        index.ts
                            │
            ┌───────────────┴────────────────┐
            ▼                                ▼
       core/policy.ts                  core/enforcer.ts
            │                                │
            ├──► role-graph.ts               ├──► effective.ts ──► memo.ts
            ├──► matcher.ts                  ├──► matcher.ts
            ├──► conditions.ts               ├──► conditions.ts
            └──► freeze.ts                   ├──► role-graph.ts (transitive set)
                                             ├──► audit/hook.ts (optional inject)
                                             └──► errors/base.ts

types/* — type-only, never imported at runtime
errors/* — leaf, no internal deps
audit/* — leaf, depends only on types
builder/* — depends on core/policy.ts (just calls definePolicy() at end)
adapters/*  — depend on core (Enforcer interface) + framework peer dep
orm/*       — depend on core/types only + ORM peer dep
react/vue   — depend on core types + React/Vue peer dep
```

There are **no circular imports** by construction. CI fails if `madge --circular`
reports anything in `src/`.

### 3.2 Data flow for a single `enforcer.check(...)` call

```
user code
   │
   │ check({ subject, action, resource, data, tenantId? })
   ▼
enforcer.check
   │ 1. validate args (cheap shape check, dev-only assert)
   │ 2. tenant guard (strictTenant ? require subject.tenantId)
   │ 3. resolveEffectivePermissions(subject.roles)   ◄── memoised
   │       (role-graph closure → flat permission map)
   │ 4. matcher.match(action, resource) over effective rules
   │       → either: deny | allow-unconditional | allow-with-condition[]
   │ 5. if conditions → evaluate (sync first; promote to async only
   │       when at least one is AsyncConditionFn)
   │ 6. emit AuditEvent { subject, action, resource, allowed, reason, ... }
   │ 7. return boolean | Promise<boolean>
   ▼
caller
```

### 3.3 Key design patterns

- **Pure factory + frozen value.** `definePolicy` and `createEnforcer` produce
  immutable data — no method on a returned object mutates `this`. Makes the
  library trivially safe to share across async work and across Workers
  isolates.
- **Compile-once, decide-many.** Role hierarchy is flattened to a transitive
  closure inside `definePolicy`; per-role permission lookup is then O(1).
- **Memoised effective-permissions table.** Tiny LRU keyed by sorted role-set
  hash — turns `check` into amortised constant time even with deep
  inheritance.
- **String-name conditions, function bodies.** The policy literal stays
  data — fully serialisable for audit dumps and easily diffable in PRs.
  Function bodies live alongside but are referenced by name. Tests can
  override individual conditions without rewriting the policy.
- **Adapters as thin glue.** Adapters never re-implement decision logic —
  they only translate framework primitives into `CheckArgs`.
- **Type inference is the spec.** The "API surface" presented to a user's IDE
  *is* their policy. We invest heavily in §4 to make that surface accurate
  and ergonomic.

---

## 4. Type System

The whole library is built around one principle: **the policy literal is the
source of truth for every type the user touches**. We never ask the user to
duplicate a string in a TS generic.

### 4.1 Core type primitives

The reviewer flagged that the previous draft's invariants in §4.3 were not
actually expressible by these types — `RoleDef<string>` accepted any string
in `extends`, so `extends: ['admn']` would compile. Fixed with a separate
`ValidatePolicy<P>` brand applied via intersection at the `definePolicy`
signature; the literal `P` is then walked once and every cross-reference
(`extends`, action keys, condition refs) is bound back to its real literal
union. This is the only place we accept type-system gymnastics — it is the
headline feature of the library.

```ts
// types/policy.ts
export type ActionString = string;
export type ResourceString = string;
export type RoleString = string;
export type ConditionName = string;

export interface RoleDef<TRole extends RoleString = RoleString> {
  /** Roles this role inherits permissions from. */
  readonly extends?: ReadonlyArray<TRole>;
  /** Optional human-readable description for audit/UX. */
  readonly description?: string;
  /**
   * Allow checks across tenants. Default false. Audit-flagged when true.
   * NOTE: by itself, `crossTenant: true` does NOT bypass tenant checks —
   * the call site must additionally pass `allowCrossTenant: true`. See §2.2.
   */
  readonly crossTenant?: boolean;
}

export interface ResourceDef<TAction extends ActionString = ActionString> {
  readonly actions: ReadonlyArray<TAction>;
  readonly description?: string;
}

/**
 * Composable rule shape — fully symmetric. The previous draft mixed
 * `when: T | T[]` (AND) with `anyOf` (OR) and an ad-hoc `not`; the reviewer
 * correctly pointed out that asymmetric shapes are the ones users
 * misremember. New shape:
 *
 *   - `true`             — unconditional allow
 *   - `{ allOf: [...] }` — every named condition must pass
 *   - `{ anyOf: [...] }` — at least one condition must pass
 *   - `{ not: <Rule> }`  — boolean inverse of a nested rule
 *   - `{ when: <Cond> }` — *sugar* for `{ allOf: [<Cond>] }` (single-condition
 *                         shortcut; transparently rewritten by definePolicy)
 *
 * Combinators nest, so `{ allOf: [{ anyOf: ['isOwner', 'isAdmin'] }, 'sameTenant'] }`
 * expresses "(owner OR admin) AND sameTenant" without further primitives.
 */
export type RuleDef<TCond extends ConditionName = ConditionName> =
  | true
  | { readonly when: TCond }
  | { readonly allOf: ReadonlyArray<TCond | RuleDef<TCond>> }
  | { readonly anyOf: ReadonlyArray<TCond | RuleDef<TCond>> }
  | { readonly not: TCond | RuleDef<TCond> };

/**
 * Optional `priority?: number` makes ordering an explicit contract instead of
 * load-bearing implicit state. Higher priority wins; equal priority resolves
 * by declaration order (which is itself stable because permissions live in
 * an object literal). Default 0.
 */
export type RuleObject<TCond extends ConditionName = ConditionName> = {
  readonly rule: RuleDef<TCond>;
  readonly priority?: number;
};

export type ResourcePermissions<
  R extends ResourceDef,
  TCond extends ConditionName,
> =
  | ReadonlyArray<R['actions'][number] | '*'>
  | { readonly [A in R['actions'][number]]?: RuleDef<TCond> | RuleObject<TCond> }
  | { readonly '*'?: RuleDef<TCond> | RuleObject<TCond> };

/**
 * The conditions table. Functions are tagged at registration via
 * `defineCondition()` (sync) or `defineAsyncCondition()` (async); untagged
 * arrows are accepted but treated as async for safety. The previous draft
 * detected sync vs. async via the `AsyncFunction` constructor or by invoking
 * the function and inspecting the return value — both heuristics are wrong:
 * the constructor check misses arrow-functions returning a Promise, and the
 * speculative invoke double-evaluates side-effecting conditions. Tagging
 * removes the ambiguity at policy-compile time.
 */
export type ConditionEntry =
  | TaggedSyncCondition
  | TaggedAsyncCondition
  | AsyncConditionFn; // untagged → treated as async

export interface PolicySpec {
  readonly version?: string;
  readonly roles: { readonly [R in string]: RoleDef<string> };
  readonly resources: { readonly [Res in string]: ResourceDef };
  readonly conditions?: { readonly [C in string]: ConditionEntry };
  readonly permissions: {
    readonly [R in string]?: {
      readonly [Res in string]?: ResourcePermissions<ResourceDef, string>;
    };
  };
}

/**
 * `ValidatePolicy<P>` walks the literal `P` and rebuilds every cross-reference
 * with the *literal* union it must belong to. Intersected with the user spec
 * via `definePolicy<const P>(spec: P & ValidatePolicy<P>)`, it turns mistyped
 * keys into a TS error at the policy-definition site. Sketch (full type lives
 * in `types/validate.ts`):
 *
 *   type ValidatePolicy<P extends PolicySpec> = {
 *     roles: { [R in keyof P['roles']]: RoleDef<keyof P['roles'] & string> };
 *     permissions: {
 *       [R in keyof P['permissions']]?: {
 *         [Res in keyof P['resources']]?:
 *           ResourcePermissions<P['resources'][Res], InferConditions<P>>;
 *       };
 *     };
 *   };
 *
 * Every row of §4.3 below is enforced by ValidatePolicy — and tested in
 * `test/types/inference.test-d.ts`.
 */
export type ValidatePolicy<P extends PolicySpec> = /* see types/validate.ts */ unknown;

export function definePolicy<const P extends PolicySpec>(
  spec: P & ValidatePolicy<P>,
): Policy<P>;

/** Result of `definePolicy(spec)`. Carries the literal `P` for inference. */
export interface Policy<P extends PolicySpec> {
  readonly spec: P;
  /** Branded so `Policy<A>` is not assignable to `Policy<B>`. */
  readonly __brand: 'authkit/policy';
}
```

#### 4.1.1 Condition tagging helpers

```ts
// types/condition.ts
export interface TaggedSyncCondition<TArgs = ConditionArgs> {
  (args: TArgs): boolean;
  readonly __authkitMode: 'sync';
}
export interface TaggedAsyncCondition<TArgs = ConditionArgs> {
  (args: TArgs): Promise<boolean>;
  readonly __authkitMode: 'async';
}

/**
 * Tag a sync condition so the engine knows it can run on the `checkSync`
 * fast-path. The brand is preserved through the type system but stripped
 * from the runtime payload at `definePolicy` time (no extra bytes shipped).
 */
export function defineCondition<TArgs = ConditionArgs>(
  fn: (args: TArgs) => boolean,
): TaggedSyncCondition<TArgs>;

export function defineAsyncCondition<TArgs = ConditionArgs>(
  fn: (args: TArgs) => Promise<boolean>,
): TaggedAsyncCondition<TArgs>;
```

### 4.2 Inference helpers (the "magic")

```ts
// types/inference.ts

/** Union of every role name declared in a policy. */
export type InferRoles<P extends PolicySpec> = keyof P['roles'] & string;

/** Union of every resource name. */
export type InferResources<P extends PolicySpec> = keyof P['resources'] & string;

/** Union of every action declared for resource R. */
export type InferActions<
  P extends PolicySpec,
  R extends InferResources<P>,
> = P['resources'][R] extends ResourceDef<infer A> ? A : never;

/** Union of all condition names declared in `conditions`. */
export type InferConditions<P extends PolicySpec> =
  P['conditions'] extends Record<string, unknown>
    ? keyof P['conditions'] & string
    : never;

/** Map of condition-name → typed function (sync or async). */
export type InferConditionMap<P extends PolicySpec> =
  P['conditions'] extends infer C extends Record<string, ConditionFn | AsyncConditionFn>
    ? { readonly [K in keyof C]: C[K] }
    : Record<string, never>;

/** Subject type carrying compile-time-validated role union. */
export interface Subject<TRole extends RoleString = RoleString> {
  readonly id: string;
  readonly roles: ReadonlyArray<TRole>;
  readonly tenantId?: string;
  readonly attrs?: Readonly<Record<string, unknown>>;
}
```

### 4.3 Compile-time invariants (what the type system enforces)

Each row below is enforced by `ValidatePolicy<P>` (§4.1) intersected with
the user spec at the `definePolicy<const P>(spec: P & ValidatePolicy<P>)`
boundary. The reviewer correctly flagged that the previous draft's
`RoleDef<string>` accepted any string in `extends`; `ValidatePolicy` now
walks the literal `P` and rebinds each cross-reference to the actual
literal union from the spec. **Every row in this table is exercised in
`test/types/inference.test-d.ts`** (`vitest --typecheck`), so a
regression in the validator fails CI.

| Mistake | Caught by | Diagnostic |
|---|---|---|
| `enforcer.check({ resource: 'documnt', action: 'read' })` | `R extends InferResources<P>` | `Type '"documnt"' is not assignable to type '"project" \| "document"'` |
| `enforcer.check({ resource: 'document', action: 'rea' })` | `A extends InferActions<P, R>` | `Type '"rea"' is not assignable to type '"create" \| "read" \| ...'` |
| `permissions.member.document = ['delet']` (typo) in `definePolicy` | `ValidatePolicy<P>` rebinds action keys to the resource's literal `actions[number]` | `Type '"delet"' is not assignable to type '"create" \| "read" \| ...'` |
| `roles.member.extends = ['admn']` | `ValidatePolicy<P>` rebinds `extends` to `keyof P['roles']` | `Type '"admn"' is not assignable to type '"owner" \| "admin" \| ...'` |
| Referencing missing condition `{ when: 'isOwnr' }` | `ValidatePolicy<P>` rebinds rule condition refs to `InferConditions<P>` | `Type '"isOwnr"' is not assignable to type '"isOwner" \| "sameTenant"'` |
| Mixing `data: { wrongShape }` against augmented `ResourceDataMap` | call-site `R extends keyof ResourceDataMap` narrowing (§4.4) | `Type '{ wrongShape: number; }' is not assignable to type '{ id: string; ownerId: string; tenantId: string; }'` |
| `subject.roles = ['guest']` when `guest` not in policy | `Subject<InferRoles<P>>` | `Type '"guest"' is not assignable to type '"viewer" \| ...'` |

### 4.4 Conditional & template-literal magic — only where it earns its keep

We **deliberately avoid** clever type-level computation when it does not add a
real DX win:

- ❌ No "compile-time policy compilation" returning a giant mapped type — its
  cost in IDE responsiveness on real-world policies (>40 actions × >20
  resources) outweighs the benefit.
- ❌ No `Result`-typed `check()` with discriminated unions for the happy path —
  noisy at every call site.
- ✅ We do narrow `data` to a per-resource shape via an optional augmentation
  module declared by users in their app:

```ts
// in user code (optional)
declare module '@authkit/permissions' {
  interface ResourceDataMap {
    document: { id: string; ownerId: string; tenantId: string };
    project:  { id: string; tenantId: string };
  }
}
```

…which makes `data` strongly typed **at the call site** (not just inside
the condition body):

```ts
enforcer.check({
  subject,
  resource: 'document',
  action: 'update',
  // ↓ TS error: Property 'ownerId' is missing in type '{ wrongShape: number }'
  data: { wrongShape: 1 },
});
```

…and inside conditions:

```ts
conditions: {
  isOwner: defineCondition(({ subject, resource, resourceType }) => {
    // resourceType is narrowed to 'document' | 'project'; resource has the
    // matching shape from ResourceDataMap when passed.
    return resource?.ownerId === subject.id;
  }),
};
```

Resources without an entry in `ResourceDataMap` fall back to
`Record<string, unknown>` so consumers can adopt the augmentation gradually.

---

## 5. Error Handling Strategy

### 5.1 One error class, typed codes

```ts
// errors/codes.ts
export const ERROR_CODES = {
  INVALID_POLICY:                'INVALID_POLICY',           // thrown from definePolicy
  ROLE_CYCLE:                    'ROLE_CYCLE',
  UNKNOWN_ROLE:                  'UNKNOWN_ROLE',
  UNKNOWN_RESOURCE:              'UNKNOWN_RESOURCE',
  UNKNOWN_ACTION:                'UNKNOWN_ACTION',
  UNKNOWN_CONDITION:             'UNKNOWN_CONDITION',
  TENANT_REQUIRED:               'TENANT_REQUIRED',          // strictTenant violation
  TENANT_MISMATCH:               'TENANT_MISMATCH',
  CONDITION_THREW:               'CONDITION_THREW',
  ASYNC_CONDITION_IN_SYNC_PATH:  'ASYNC_CONDITION_IN_SYNC_PATH',
  AUDIT_FAILED:                  'AUDIT_FAILED',             // emitted under auditFailureMode='deny'
  FORBIDDEN:                     'FORBIDDEN',                // thrown by enforce()
} as const;

export type ErrorCode = typeof ERROR_CODES[keyof typeof ERROR_CODES];
```

```ts
// errors/base.ts
export class PermissionError extends Error {
  override readonly name = 'PermissionError';
  readonly code: ErrorCode;
  /** Structured context for audit logs / Sentry. Never contains PII by default. */
  readonly context?: Readonly<Record<string, unknown>>;
  /** Original error, when wrapping a thrown condition. */
  override readonly cause?: unknown;

  constructor(
    code: ErrorCode,
    message: string,
    context?: Record<string, unknown>,
    cause?: unknown,
  );
}
```

### 5.2 When to throw vs return a boolean

| Surface | Behaviour | Rationale |
|---|---|---|
| `definePolicy` | **throws** on invalid input | Configuration errors must crash fast at boot |
| `enforcer.check` | returns `Promise<boolean>` on allow/deny — never throws on rule mismatch | Hot path; caller decides what to do |
| `enforcer.checkSync` | returns `boolean` OR throws `ASYNC_CONDITION_IN_SYNC_PATH` if any matched condition is async | Surface the bug at call time, not via a silent allow |
| `enforcer.enforce` | throws `PermissionError(FORBIDDEN)` on deny | Convenience for HTTP/RPC handlers |
| `enforcer.explain` | **never throws** (except for ROLE_CYCLE / UNKNOWN_*) | Designed for tests/audit |
| Condition function throws | engine **catches**, decision is **deny**, audit emits with `cause`. Original error is **NOT** re-thrown to `check()` callers | Re-throwing meant a careless `try { allow = await check() } catch { allow = true }` could grant access on a buggy condition. Fail-closed-and-observable instead |
| Condition returns non-`true` | strict equality check — only `=== true` allows. Truthy strings, objects, numbers all deny and emit a dev-only warning | `Boolean({})` is `true`; the implicit-return bug must not grant admin in production |
| `strictTenant: true` + missing `tenantId` | **throws** `TENANT_REQUIRED` from `check` | Tenant-leakage is a security incident, not a deny |
| `auditFailureMode: 'deny'` + audit hook throws | `check` returns `false`, emits synthetic `AUDIT_FAILED` audit event | Strict SOC2 mode — if the compliance trail is broken, fail closed |

There is **no `Result<T, E>` discriminated union** in the public API. The
report flagged "5-minute getting started" as a key DX promise — `Result` types
double the call-site noise for negligible safety gain in this domain. Errors
that *can* be ignored are `boolean`; errors that *must* be handled at boot
are thrown.

### 5.3 Audit emission on errors

A condition that throws produces an audit event:

```ts
{
  ts: 1745000000000,
  decision: 'deny',
  reason: 'CONDITION_THREW',
  conditionName: 'isOwner',
  cause: 'TypeError: Cannot read properties of undefined',
  subject: { id: 'u_1', roles: ['member'], tenantId: 't_1' },
  action: 'update',
  resource: 'document',
  data: { id: 'd_42' },
}
```

The error is **not re-thrown** from `check()` (see §5.2 — the previous draft
did re-throw, which the reviewer correctly flagged as enabling a privilege
escalation via overly-broad `try/catch`). Instead, the audit event is the
single observability signal — application monitoring (Datadog, Sentry) is
expected to alert on `decision: 'deny' && reason: 'CONDITION_THREW'`. Worked
example for the README:

```ts
audit: (event) => {
  if (event.decision === 'deny' && event.reason === 'CONDITION_THREW') {
    Sentry.captureException(event.cause, { tags: { kind: 'authz' } });
  }
  logger.info({ msg: 'authz', ...event });
},
```

---

## 6. Bundle & Tree-shaking Plan

Target from the report: `min_bundle_size_kb: 2.8`, `target_bundle_size_kb: 5`.

### 6.1 Entry points (subpath exports)

| Subpath | Purpose | Size budget (gzipped, minified) |
|---|---|---|
| `.` (root) | core: `definePolicy`, `createEnforcer`, `defineCondition`, types, `PermissionError`, `accessibleBy` (filter AST builder only) | **5 KB** |
| `./errors` | error class + codes constant only | 0.4 KB |
| `./audit` | `composeAudit`, default JSON formatter, timing wrapper | 0.5 KB |
| `./builder` | optional fluent DSL builder | 0.8 KB |
| `./types` | type-only (zero runtime) | 0 KB |
| `./adapters/next` | App Router wrappers + middleware | 1 KB |
| `./adapters/hono` | middleware factory | 0.6 KB |
| `./adapters/express` | middleware factory | 0.6 KB |
| `./adapters/fastify` | plugin factory | 0.7 KB |
| `./adapters/nestjs` | guard + decorator + module | 1.5 KB |
| `./adapters/trpc` | middleware factory | 0.6 KB |
| `./orm/prisma` | role/membership loader + `toPrismaWhere` | 0.7 KB |
| `./orm/drizzle` | role/membership loader + `toDrizzleWhere` | 0.7 KB |
| `./orm/mongoose` | role/membership loader + `toMongoFilter` | 0.7 KB |
| `./react` | provider + hook + component | 1.2 KB |
| `./vue` | plugin + composable + component | 1 KB |

ESM-only across every entry. Node 20+ is the floor (Node 18 EOL'd
2025-04-30, Node 20 EOLs 2026-04-30 — the docs/examples target Node 22+),
so the dual-package hazard that bites authz code (two `instanceof
PermissionError` realms when a CJS and an ESM copy load) is gone by
construction. `size-limit` runs in CI with these budgets — a regression
fails the PR.

### 6.2 Tree-shaking guarantees

- `package.json` has `"sideEffects": false` — proven free of side-effects by
  static analysis (no top-level expression with a side-effect; freezing is
  scoped inside factory functions).
- Each subpath has its own ESM file in `dist/<sub>/index.js` — no barrel
  re-exports the user did not explicitly import.
- We never `import './polyfill'` or auto-register globals.
- Constants like `ERROR_CODES` are exported via `export const ERROR_CODES =
  Object.freeze({ ... })` — bundlers fold dead branches when only one code
  is referenced.

### 6.3 Build pipeline

`tsup` with the following config (rationale in §8):

- `format: ['esm']` — ESM-only across every entry. Node 18 is EOL,
  Node 20 EOLs 2026-04-30, every supported framework, runtime, and
  bundler ships native ESM in 2026. Dropping CJS removes a build artifact,
  simplifies `attw`, and eliminates the dual-package-hazard class of
  bugs that is especially nasty for authz (two `instanceof
  PermissionError` realms in the same process).
- `dts: true` — emits `.d.ts` next to JS, walks subpath entries.
- `treeshake: 'recommended'` — Rollup-flavoured shaking on top of esbuild.
- `splitting: false` — avoids hash-named common chunks that complicate
  subpath exports.
- `target: 'es2024'` — supported by Node 22, current browsers, Workers,
  Deno and Bun (2026-vintage). Lets us keep the `using`/`Object.groupBy`
  output instead of polyfilling.

### 6.4 Verification in CI

- `size-limit` against the budgets above.
- `@arethetypeswrong/cli` (`attw --pack`) — guarantees correct ESM/CJS dual
  package and accurate `types` resolution per subpath.
- `publint` — catches malformed `exports` / `files` fields before publish.

---

## 7. Dependencies

### 7.1 Runtime — zero

The market analysis ranks "zero deps" as a top differentiator against CASL
(several deps) and Casbin (~20). We commit to **zero** runtime `dependencies`.

Specifically we **do not** depend on:

- `lodash` / `lodash-es` — the few helpers we need (≤ 30 LOC) are vendored
  into `src/utils/`.
- `tslib` / `@swc/helpers` — `target: 'es2022'` lets the TS compiler emit
  native `class`, `?.`, `??=` etc. without runtime helpers.
- `zod` / `valibot` for policy validation — the policy is validated by a
  tiny hand-written validator (≈80 LOC, dev-only branch elided in prod
  builds). Adding zod would multiply the bundle 6×.

### 7.2 Peer dependencies — opt-in per adapter

```
react       >=18 <20    optional
vue         >=3.4 <4    optional
next        >=13.4 <16  optional
hono        >=4 <5      optional
express     >=4 <6      optional
fastify     >=4 <6      optional
@nestjs/common >=10 <12 optional
@trpc/server   >=11 <13 optional
@prisma/client >=5 <7   optional
drizzle-orm    >=0.30 <1 optional
mongoose       >=7 <9   optional
```

Runtime floor: **Node 20** in `engines` (Node 18 EOL'd 2025-04-30; today is
2026-04-28). Examples and docs target Node 22 to lean on native ESM and
ES2024 features without polyfills.

All marked `optional` in `peerDependenciesMeta` — installing the core does
not force install of any framework. The version ranges are pinned via the
**range pattern** `>=X.Y <Z` (open upper bound at the next major) so we
don't have to chase patch releases.

### 7.3 Dev dependencies — minimal but production-grade

Categories:

- **Build & types**: `typescript`, `tsup`, `@arethetypeswrong/cli`, `publint`
- **Test**: `vitest`, `@vitest/coverage-v8`, `@cloudflare/vitest-pool-workers`,
  `@testing-library/react`, `@vue/test-utils`
- **Lint/format**: `@biomejs/biome` — single tool replacing eslint+prettier;
  10× faster CI lint step.
- **Size**: `size-limit` + `@size-limit/preset-small-lib`
- **Release**: `@changesets/cli`
- **Framework dev-deps for testing adapters**: hono, express, fastify, next,
  react, react-dom, vue, drizzle-orm, mongoose, @prisma/client,
  @trpc/server, @nestjs/common, @types/express, @types/node,
  @types/react, @types/react-dom

---

## 8. Configuration

### 8.1 `tsconfig.json`

```jsonc
{
  "compilerOptions": {
    "target": "ES2024",
    "lib": ["ES2024", "DOM", "DOM.Iterable"],
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noPropertyAccessFromIndexSignature": false,
    "exactOptionalPropertyTypes": true,
    "useUnknownInCatchVariables": true,
    "isolatedModules": true,
    "verbatimModuleSyntax": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "esModuleInterop": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "jsx": "react-jsx",
    "types": ["node"]
  },
  "include": ["src", "test"]
}
```

`tsconfig.build.json` extends the above and excludes `test/` and JSX runtime.

### 8.2 `vitest.config.ts` (sketch)

- Default `node` environment for `test/core/**`.
- `jsdom` for `test/react/**`.
- `@cloudflare/vitest-pool-workers` for `test/runtime/workers.test.ts`.
- `typecheck.enabled = true`, `typecheck.include = ['test/**/*.test-d.ts']`.
- Coverage thresholds: `lines 95`, `functions 95`, `branches 90` — security
  library, no excuses.

### 8.3 `package.json` highlights

- `"name": "@authkit/permissions"`, `"version": "0.1.0"`, `"type": "module"`,
  `"sideEffects": false`.
- `"exports"` enumerates every subpath listed in §6.1 — **ESM-only**, no
  `require` resolutions and no `main` field. The dual-package hazard is
  particularly bad for authz code (two `instanceof PermissionError`
  identities in the same process), so we skip CJS entirely.
- `"engines": { "node": ">=20" }` — Node 18 EOL'd 2025-04-30; Node 20 is
  the floor as of 2026-04-28. Examples target Node 22.
- Scripts: `build`, `dev`, `test`, `test:types` (= `vitest run --typecheck`,
  no separate `tsd` dep — the reviewer correctly flagged the duplication),
  `test:coverage`, `bench`, `lint`, `format`, `size`, `publint`, `attw`,
  `release`, `prepublishOnly` (chains `build → publint → attw → size`).
- `size-limit` array enforces the §6.1 budgets.
- `publishConfig.provenance: true` — npm provenance attestations.

(See the actual `package.json` committed alongside this plan.)

### 8.4 `.gitignore`

Standard Node + TS + tooling. Pattern rules — no `./` prefix; trailing slash
intentionally omitted so both files and directories with that name are
matched.

---

## 9. Edge Cases

### 9.1 Policy-level (caught at `definePolicy`)

1. **Role cycle.** `a extends [b]`, `b extends [a]` → `ROLE_CYCLE` thrown at
   policy compile time. DFS with grey/black colouring; error message names
   the full cycle.
2. **Self-extension.** `a extends [a]` → same as cycle.
3. **Unknown role in `extends`.** `member extends ['superuser']` where
   `superuser` is not a key of `roles` → `UNKNOWN_ROLE`.
4. **Unknown resource in `permissions`.** `permissions.admin.documnt` →
   `UNKNOWN_RESOURCE`.
5. **Unknown action in resource permission.** `permissions.admin.document.delet`
   → `UNKNOWN_ACTION`.
6. **Unknown condition referenced from a rule.** `{ when: 'isOwnr' }` →
   `UNKNOWN_CONDITION`.
7. **Empty `actions` array on a resource.** Allowed but warned — typically a
   work-in-progress; emits `audit` once on first `check` against the
   resource (dev only).
8. **Mixed array + object permission shape on the same resource.** Disallowed
   by the type system; runtime validator double-checks.
9. **Wildcard `*` listed alongside concrete actions.** Normalised to `*`
   only — concrete entries become redundant but are allowed and stripped.
10. **Deeply nested role inheritance (>32 levels).** Allowed but the LRU
    capacity adjusts to ensure the closure is still computed in linear
    time. We don't impose an arbitrary depth limit.
11. **Frozen-input mutation.** `policy.spec.roles.admin = {}` throws in
    strict mode, silently fails otherwise. We freeze recursively
    (`deepFreeze`) on first construction.

### 9.2 Subject / runtime check edge cases

1. **No roles on subject** (`subject.roles = []`). Always denies; emits
   audit with `reason: 'NO_ROLES'`.
2. **Role on subject not declared in policy.** Denies, audit
   `reason: 'UNKNOWN_ROLE_ON_SUBJECT'` — never throw, because production
   subjects can survive policy-spec churn while a deploy is rolling.
3. **`tenantId` missing in `strictTenant` mode.** Throws `TENANT_REQUIRED`.
4. **`tenantId` mismatch** between `subject.tenantId` and `data.tenantId`.
   Denies and audits `reason: 'TENANT_MISMATCH'`. Cross-tenant access
   requires **two independent opt-ins** (defence in depth):
   - the subject's role declares `crossTenant: true` in the policy, AND
   - the call site explicitly passes `allowCrossTenant: true`.

   Either alone is insufficient — a misjoined membership row at the DB
   layer cannot, by itself, cause a cross-tenant leak. Audit always carries
   both tenant ids so incident response can locate the leak.
5. **Action called on resource with no rule for any of the subject's roles.**
   Denies (default-deny). Audit `reason: 'NO_MATCHING_RULE'`.
6. **Conflicting decisions across the rule set.** The model is **purely
   additive (allow-only with default-deny)**. The previous draft promised
   "explicit deny wins, then explicit allow, then wildcard allow, then
   wildcard deny, then default deny" — but `RuleDef` has no `deny` shape,
   so that precedence was unimplementable as written. Two fixes were on
   the table; we picked the simpler one:
   - rules can only **add** permissions (no top-level `deny`),
   - negation lives inside an `allow` rule via `{ not: <Cond | Rule> }`,
   - default-deny applies when no rule grants the action.

   Ordering within a single resource is **deterministic**: rules are
   evaluated by `priority` descending (default `0`); ties resolve by
   declaration order in the policy literal. Captured in the §4.2 contract
   so refactors that re-order keys do not silently change behaviour. If a
   future major version needs explicit deny rules, we'll add a top-level
   `denyPermissions` block — *not* shoehorn it into `RuleDef`.
7. **Sync vs. async condition dispatch.** Conditions are tagged at policy-
   compile time via `defineCondition()` (sync) or `defineAsyncCondition()`
   (async). The engine **never speculatively invokes** a function to find
   out which it is — that path was rejected because heuristics miss
   arrow-functions returning Promises and double-evaluate side-effecting
   conditions. Untagged functions are accepted (back-compat with terse
   inline conditions) but treated as **async**, since the cost of a
   spurious async path is one Promise allocation, while the cost of a
   spurious sync path is a silent-allow security bug.
8. **Condition throws synchronously or rejects.** Caught by the engine,
   decision is **deny**, audit emits with `cause`. The error is **not**
   re-thrown to `check()` callers — re-throwing meant a permissive
   `try/catch` upstream could grant access on a buggy condition (the
   reviewer's point: "Pick one: either deny + emit audit + return false,
   or re-throw without claiming the decision is deny"). Application
   monitoring hooks the audit event for alerting (see §5.3 worked example).
9. **Condition returns a non-`true` value.** Strict equality only — only
   `result === true` allows; everything else (truthy strings, objects,
   `Boolean({})`, missing return → `undefined`) **denies** and emits a
   dev-only `NON_BOOLEAN_CONDITION_RESULT` warning. The previous
   `Boolean(result)` coercion is the textbook implicit-allow footgun.
10. **Resource `data` undefined when condition expects it.** Each condition
    is documented to handle `data === undefined`. The default conditions
    (`sameTenant`, `isOwner`) deny when data is missing.
11. **Multiple roles producing conflicting decisions.** Same deterministic
    resolution as §9.2.6: priority-descending, declaration-order tie-break.
12. **Effective-permissions cache key.** The previous draft hashed the
    sorted role tuple via FNV-1a 32-bit over a joined string. The reviewer
    correctly flagged that *any* hash collision in an authz cache can
    grant a subject the effective permissions of a different role-set —
    "<2⁻³⁰" is unacceptable for security-critical state. **We use the
    sorted-joined role string itself as the LRU key.** String interning
    makes lookups just as fast and the collision probability is exactly
    zero. The cost is a slightly longer key for users with 50+ roles per
    subject, which is negligible compared to the compiled rule table the
    cache references.
13. **Race condition under high concurrency on the same Enforcer
    instance.** All caches are read-only after first compute; concurrent
    writes are idempotent (same input produces same compiled output) so
    we don't need locks. Verified with `vitest --concurrency`.

### 9.3 Runtime-portability edge cases

1. **Cloudflare Workers / Vercel Edge — no `process` global.** Optional
   chaining like `process?.env?.NODE_ENV` still throws `ReferenceError`
   in Workers and Deno when `process` is not declared as a global at all
   — `?.` only protects against `null`/`undefined`, not undeclared
   identifiers. **All env probes go through `utils/env.ts::isDev()`**
   which uses the only portable form:
   ```ts
   typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production'
   ```
   Direct `process.env` reads are banned via a Biome rule so the §9.7
   edge-runtime smoke test cannot pass while the dev-mode warning path
   blows up in real Workers.
2. **Workers — no `Buffer`.** No reliance on Buffer; the cache key is the
   raw sorted-role string (no hashing) so we don't need any binary
   primitive.
3. **Workers — no FS.** No FS access at runtime (all data lives in the
   policy object).
4. **Bun / Deno** — verified via cross-runtime CI (subset of tests pinned
   to each).
5. **React Server Components.** `react` adapter exports a server-safe
   `useCanServer` that never reaches for the React context; tested with
   `next` `15+` App Router. The `<PermissionProvider>` is `'use client'`.
6. **Tree-shaking on bundlers without ESM-aware tree-shake (Webpack 4).**
   Documented as unsupported — the report's `runtime_targets` start at
   modern ES2020+ runtimes; Webpack 4 is out of scope.

### 9.4 Audit & observability edge cases

1. **Audit hook throws or rejects.** Behaviour is governed by the new
   `auditFailureMode` option (§2.2):
   - `'log'` (default) → `console.error` and continue with the original
     decision. UI-friendly default — the request must not be denied
     because Datadog is down.
   - `'throw'` → re-throws after the decision so a global error handler
     can surface the broken pipeline.
   - `'deny'` → fails closed: `check` returns `false` and emits a
     synthetic `AUDIT_FAILED` event. Recommended for SOC2 customers who
     treat the audit log as a compliance artifact.
2. **Audit hook is async on Cloudflare Workers.** The previous draft
   scheduled the hook via `queueMicrotask` to keep the sync `check`
   fast-path. The reviewer correctly pointed out that on Workers the
   request execution context terminates when `Response` is returned;
   pending microtasks scheduled after that are **not guaranteed to run**.
   For SOC2 customers, dropping audit events is a compliance bug. Two
   fixes are now in the API:
   - `check()` is always-async, so the audit hook always has a real
     awaitable boundary to ride on.
   - `EnforcerOptions.waitUntil?: (p: Promise<unknown>) => void` lets
     the Workers / Vercel adapter pipe `ctx.waitUntil` into the enforcer
     so audit promises survive past the response.
3. **High-cardinality tenant id leaking into metrics.** Stripping
   `tenantId` to an 8-char hash is **opt-in** via
   `audit/formatter::tenantHashFormatter` — the previous "auto-detect
   integration with console" was security theatre (32-bit hashes of
   sequential ids enumerate trivially) and surprised users who actually
   wanted full tenant ids in their logs.

### 9.5 Policy migration & version skew

1. **Policy version field.** `definePolicy` accepts `version: string` —
   audit events include it, allowing post-incident attribution.
2. **Removed action while subjects still reference it.** A subject role
   referencing a removed action simply has no rule — denies cleanly. No
   crash.
3. **Renamed role.** Subjects with the old role get `UNKNOWN_ROLE_ON_SUBJECT`
   denies until they re-authenticate. Migration recipe documented in
   README (dual-role grace period).

---

## 10. Out of Scope (1.0)

Stating what we are **not** shipping is just as important as the feature
list — it tells contributors where the boundary lives and tells users where
to look elsewhere.

- **Authentication.** Lives in the sibling `@authkit/session` library;
  this package only consumes a `Subject` produced upstream.
- **Persistence of roles / users / memberships.** We expose ORM-shaped
  *adapters* (`loadSubject`, filter translators) but do not run any
  migrations, manage schemas, or cache rows. Storage is the application's
  problem.
- **Field-level / attribute-level filtering** (e.g. CASL's
  `accessibleFieldsBy`, accesscontrol's `denyAll/allowAll/specific
  fields`). The reviewer flagged this as missing; we are deferring to
  1.x rather than including it now because (a) the type-shape is
  non-trivial under the `ResourceDataMap` augmentation pattern, and
  (b) row-level filtering via `accessibleBy` (§2.5) covers the most
  common SOC2 row-isolation case. Field-level lands when we have
  concrete user demand and a clean API draft. Tracked publicly as a
  1.x roadmap item.
- **ReBAC / Zanzibar relationship graphs.** OpenFGA, WorkOS FGA and
  Auth0 FGA already cover this nichewell; chasing them on their own
  turf is a losing fight. The market report (id `03`) explicitly calls
  out lightweight as the wedge.
- **Policy-as-code DSL** (Rego, Polar, Casbin's PERM/CONF). The whole
  library is built on the inverse premise: *policy is a value, not a
  config file*. Adding a DSL would dilute that.
- **UI policy builder.** Commercial niche of Permit.io.
- **CommonJS distribution.** ESM-only — see §6.3.

---

## Appendix A — Worked example (end-to-end DX)

```ts
// policy.ts
import { definePolicy, defineCondition } from '@authkit/permissions';

export const policy = definePolicy({
  version: '2026-04-28',
  roles: {
    owner:  { extends: ['admin'] },
    admin:  { extends: ['member'] },
    member: { extends: ['viewer'] },
    viewer: {},
    superadmin: { extends: [], crossTenant: true },
  },
  resources: {
    project:  { actions: ['create', 'read', 'update', 'delete', 'invite'] },
    document: { actions: ['create', 'read', 'update', 'delete', 'comment'] },
  },
  conditions: {
    isOwner:    defineCondition(({ subject, resource }) => resource?.ownerId === subject.id),
    sameTenant: defineCondition(({ subject, resource }) => resource?.tenantId === subject.tenantId),
  },
  permissions: {
    viewer: {
      project:  ['read'],
      document: ['read', 'comment'],
    },
    member: {
      document: {
        create: { when: 'sameTenant' },                       // sugar for { allOf: ['sameTenant'] }
        update: { allOf: ['isOwner', 'sameTenant'] },         // explicit AND
      },
    },
    admin: {
      project:  ['create', 'update', 'invite'],
      document: ['delete'],
    },
    owner: {
      project:  ['*'],
      document: ['*'],
    },
    superadmin: {
      project:  ['*'],
      document: ['*'],
    },
  },
});

// enforcer.ts
import { createEnforcer } from '@authkit/permissions';
import { policy } from './policy';
export const enforcer = createEnforcer(policy, {
  audit: (event) => logger.info({ msg: 'authz', ...event }),
  auditFailureMode: 'log',          // SOC2-strict shops: 'deny'
});

// any handler
import { enforcer } from './enforcer';

await enforcer.enforce({
  subject: { id: user.id, roles: user.roles, tenantId: user.tenantId },
  action: 'update',
  resource: 'document',
  data: doc,
});
// — throws PermissionError(FORBIDDEN) on deny; otherwise returns void.
```

The IDE autocompletes `'update'` after the user types `action: '`, autocompletes
`'document'` after `resource: '`, and underlines a typo the second the user
looks away. That is the entire promise of the library.

---

## Review Changes

This section logs every reviewer concern and the resolution applied to the
plan. Two reviews were submitted by Mykhailo Kryvytskyi (REQUEST_CHANGES on
both); items are grouped by review and listed in original order. "Agreed"
means the plan was changed; "Disagreed" means it was not, with reasoning.

### Review 1 — DX, security, competitive positioning

1. **[high — security] Cross-tenant `'*'` sentinel as privilege escalation**
   — *Agreed* (resolution overlaps with Review 2 #6). The plan never had a
   string sentinel, but the `crossTenant: true` role flag was previously
   sufficient on its own. The fail-open footgun is real: a misjoined
   membership row at the DB layer could grant a cross-tenant subject
   without any call-site signal. **Defence in depth added** — cross-tenant
   access now requires *both* the role flag AND a per-call
   `allowCrossTenant: true`. Sections updated: §2.2 `CheckArgs`, §4.1
   `RoleDef` (note added), §9.2.4.

2. **[high — DX/API] `Permissions` vs `ScopedAbility` call-shape divergence**
   — *Agreed in spirit, partially applicable*. The plan's `Enforcer`
   already used a single object shape across `check / enforce / explain`,
   so the server-side concern was not present. The same concern *did*
   apply to React's `useCan('update', 'document', doc)` (positional). The
   React adapter was switched to the same object form as the server API
   to kill the `(action, resource)` vs `(resource, action)` confusion at
   the source. Section updated: §2.4 React example.

3. **[high — competitive] No ORM/query-builder integration for
   `accessibleBy`** — *Agreed*. The `orm/{prisma,drizzle,mongoose}` subpaths
   were previously framed as role-loaders only. Added a normalized filter
   AST plus per-ORM translators (`toPrismaWhere`, `toDrizzleWhere`,
   `toMongoFilter`) so application code can push authorization into the
   SQL/Mongo `where` clause. This closes the row-level enforcement gap
   that CASL's `accessibleBy(ability)` uses as its retention hook.
   Sections updated: §1 (file layout for `orm/*/filter.ts` and
   `core/accessible.ts`), §2.5, §6.1 (size budget bumped 0.6 → 0.7 KB
   per ORM adapter).

4. **[high — type safety] §4.2 `Rule` action not narrowed by resource** —
   *Not directly applicable, but related concern addressed*. The plan's
   `ResourcePermissions<R, TCond>` already keys actions off `R['actions']`
   so the `{ resource: 'billing', action: 'publish' }` example does not
   compile in our shape. The deeper concern raised by Review 2 #5 (that
   `RoleDef<string>` does *not* narrow `extends`, and `ResourcePermissions`
   passes `string` not the literal action union) is real and resolved
   together with that item — see Review 2 below.

5. **[high — Edge runtime] `process?.env?` is not Workers-portable** —
   *Agreed*. Optional chaining only protects against `null`/`undefined`,
   not undeclared identifiers; Workers throws `ReferenceError`. Codified
   `utils/env.ts::isDev()` (`typeof process !== 'undefined' &&
   process.env?.NODE_ENV !== 'production'`) and banned direct
   `process.env` reads via a Biome rule so the §9.7 edge smoke test
   cannot pass while real Workers blow up. Sections updated: §1 (file
   layout), §9.3.1.

6. **[medium — bundle] `AbilityBuilder` in core entry / `serialize()` in
   `Permissions`** — *Partially applicable*. Builder has always lived at
   `./builder` subpath in our plan (§6.1), not in core. There was no
   `serialize()` on `Enforcer` in the previous draft. Logged here for
   transparency — no change needed. If we ever add `serialize()`, it goes
   in as a free function for the same tree-shaking reason the reviewer
   gave.

7. **[medium — security/compliance] Audit fail-soft is wrong default for
   SOC2** — *Agreed*. Replaced the boolean `strictAudit` with a tri-state
   `auditFailureMode: 'log' | 'throw' | 'deny'` (default `'log'`). Strict
   shops set `'deny'` so a broken audit pipeline fails the request closed
   with a synthetic `AUDIT_FAILED` event. Sections updated: §2.2
   `EnforcerOptions`, §5.1 `ERROR_CODES`, §5.2 table, §9.4.1.

8. **[medium — naming consistency] Five different verb patterns across
   adapters** — *Agreed*. Standardised on `<framework>Permissions(...)`
   for the middleware factory: `nextPermissions`, `honoPermissions`,
   `expressPermissions`, `fastifyPermissions`, `trpcPermissions`. NestJS
   keeps `PermissionsGuard` + `@Requires()` per framework idiom. Section
   updated: §2.4.

9. **[medium — naming] `abilityFor` vs `ScopedAbility` mismatch** — *Not
   applicable*. The plan never had `abilityFor`. Logged for transparency;
   our equivalent factory is `createEnforcer` and the returned type is
   `Enforcer<P>` — names align.

10. **[medium — type safety] `ConditionFn` doesn't carry resource literal
    forward** — *Agreed*. `data` is now narrowed at the call site (not
    just inside the condition body) via `R extends keyof ResourceDataMap`
    on `CheckArgs.data`. Adopting consumers get a TS error if the data
    shape doesn't match the augmented map. Sections updated: §2.2
    `CheckArgs`, §4.4.

11. **[medium — semantics] No `priority` field, ordering is implicit** —
    *Agreed*. Added optional `priority?: number` to a new `RuleObject`
    shape (defaults to 0; ties resolve by declaration order). Made
    deterministic ordering an explicit contract in §4.2 / §9.2.6 rather
    than a side note in the algorithm description.

12. **[low — DX] `tenantId` required is friction for single-tenant apps**
    — *No change required, clarified*. `subject.tenantId` was already
    `tenantId?: string` in §4.2; the requirement only fires under
    `strictTenant: true`, which single-tenant users disable once. Single-
    tenant adopters never have to thread a dummy string. Confirmed by
    re-reading §2.2 `EnforcerOptions.strictTenant` doc comment.

13. **[low — semantics] Empty `fields` array allowed=true is silent-permit**
    — *Not applicable*. The current plan does not have field-level
    permissions. We're explicitly putting field-level filtering out of
    scope for 1.0 (§10) — see also Review 2 #11.

14. **[low — package.json] `arethetypeswrong` should be `@arethetypeswrong/cli`,
    pick one of `tsd` vs `vitest --typecheck`** — *Already aligned*.
    `package.json` already uses `@arethetypeswrong/cli` (line 166). `tsd`
    was never in the deps; we use `vitest run --typecheck` exclusively.
    Plan §8.3 now explicitly calls this out so the reviewer's note
    doesn't recur. No package.json change needed for this item.

15. **[low — terminology] `combiningAlgorithm: 'deny-overrides'` is XACML
    jargon** — *Not applicable*. The plan never had this field. Now that
    the model is purely additive (§9.2.6), there's nothing to rename.

### Review 2 — type-safety, runtime correctness, security

1. **[critical] Hybrid sync/async `check()` return** — *Agreed*. `check()`
   is now **always-async** (`Promise<boolean>`). Added `checkSync()` that
   throws `ASYNC_CONDITION_IN_SYNC_PATH` if any matched condition was
   tagged async (or untagged). Dropped the redundant `checkAsync`.
   Sections updated: §2.2 `Enforcer`, §5.1 (new code), §5.2 table, §9.2.7.

2. **[critical] FNV-1a 32-bit cache key for authz decisions** — *Agreed*.
   Hash dropped entirely. Cache key is the sorted-joined role string itself
   — string interning makes lookup just as fast and the collision
   probability is exactly zero. Sections updated: §1 (`effective.ts`
   comment), §9.2.12.

3. **[critical] Contradictory deny semantics (§9.2.6 vs no `deny` form in
   `RuleDef`)** — *Agreed*. Picked the simpler of the two defensible
   options: model is **purely additive (allow-only with default-deny)**.
   Negation stays inside an allow rule via `{ not }`. Removed the XACML-
   style precedence claim. Section updated: §9.2.6.

4. **[critical] Node 18 floor wrong (EOL'd 2025-04-30)** — *Agreed*.
   Bumped `engines.node` to `>=20`; docs/examples target Node 22. Updated
   the opening positioning paragraph, §7.2, §8.1 (`target: ES2024`),
   §8.3, package.json `engines`.

5. **[critical] §4.3 invariants not expressed by §4.1 types** — *Agreed*.
   This is the single largest type-system fix. Added `ValidatePolicy<P>`
   intersected with the user spec at the `definePolicy<const
   P>(spec: P & ValidatePolicy<P>)` boundary. The validator walks the
   literal `P` and rebinds `extends`, action keys, and condition refs to
   their actual literal unions. Every row of §4.3 is now exercised in
   `test/types/inference.test-d.ts` so a regression fails CI. Sections
   updated: §4.1, §4.3.

6. **[major] `crossTenant: true` implicit privilege escalation** — *Agreed*
   (overlaps with Review 1 #1). Resolved via per-call `allowCrossTenant:
   true` opt-in.

7. **[major] Audit on Workers will drop events with `queueMicrotask`** —
   *Agreed*. Two-part fix: (a) `check()` is now always-async so the audit
   hook always has a real awaitable boundary; (b) added `EnforcerOptions.
   waitUntil?: (p: Promise<unknown>) => void` so Workers/Vercel adapters
   pipe `ctx.waitUntil`. Sections updated: §2.2 `EnforcerOptions`, §2.4
   Hono example, §9.4.2.

8. **[major] Condition-throws semantics contradictory** — *Agreed*. The
   engine now catches the throw, denies, and emits an audit event with
   the cause. Error is **not** re-thrown to `check()` callers. Sections
   updated: §5.2 table, §5.3, §9.2.8.

9. **[major] Non-boolean condition return coerced via `Boolean(...)`** —
   *Agreed*. Switched to **strict equality**: only `result === true`
   allows; everything else denies and emits a dev-only warning. Sections
   updated: §5.2 table, §9.2.9.

10. **[major] Async detection via `AsyncFunction` is fragile** — *Agreed*.
    Replaced the heuristic with explicit tagging via `defineCondition()`
    (sync) / `defineAsyncCondition()` (async). Untagged functions are
    accepted but treated as async — failing safe rather than fast.
    Sections updated: §1 (file comments), §4.1.1 (new helpers), §9.2.7.

11. **[major] No field-level / attribute filtering** — *Disagreed in
    timing, agreed in disclosure*. We are not adding field-level
    filtering in 1.0 because (a) the type-shape under `ResourceDataMap`
    is non-trivial, and (b) row-level filtering via `accessibleBy`
    (§2.5) covers the SOC2 row-isolation case. Explicitly listed in
    new §10 "Out of Scope" with a 1.x roadmap pointer. The reviewer's
    real complaint was that it looked forgotten — that part is fixed.

12. **[major] `RuleDef` shape asymmetric (`when` vs `anyOf` vs `not`)** —
    *Agreed*. New shape: `true | { when } | { allOf } | { anyOf } |
    { not }` where `when: TCond` is sugar for `{ allOf: [TCond] }`.
    Combinators nest, so `(owner OR admin) AND sameTenant` is just
    `{ allOf: [{ anyOf: [...] }, 'sameTenant'] }`. Section updated:
    §4.1 (new `RuleDef`).

13. **[minor] `authorize()` is the wrong verb** — *Agreed*. Renamed to
    `enforce()`. The reviewer suggested `assert` / `requireCan`; picked
    `enforce` because it pairs cleanly with `check` (the two-track error
    model the reviewer praised in Review 1's "What's good"). No backwards
    alias since we're pre-1.0. Sections updated: §2.2, §2.4 (every
    adapter call), §5.1 `FORBIDDEN` doc comment, §5.2 table, Appendix A.

14. **[minor] `data: ResourceData` is loose at call site** — *Agreed*.
    See Review 1 #10 — narrowed via `R extends keyof ResourceDataMap`.

15. **[minor] `tenantHash` formatter auto-strip is security theatre** —
    *Agreed*. Dropped the auto-detect-when-`console`-is-the-target
    behaviour. Hash-stripping is now an explicit
    `audit/formatter::tenantHashFormatter` opt-in for users who want it
    for metric-cardinality reasons (not "PII safety", which 32 bits of
    FNV doesn't actually provide). Section updated: §9.4.3.

16. **[minor] Drop CJS root entry** — *Agreed*. Every supported runtime
    ships native ESM in 2026 (Node 18 EOL, Node 20 EOLs in two days,
    Workers/Deno/Bun/all current frameworks are ESM-first). Removed
    `dist/index.cjs` from build, `main` from package.json, and the
    `require` resolutions from `exports`. Eliminates the dual-package
    `instanceof PermissionError` hazard. Sections updated: §6.1, §6.3,
    §8.3, package.json.

17. **[minor] `permissionsOf(roles)` returns "non-frozen, deep-cloned"** —
    *Agreed*. Returns `Readonly<EffectivePermissions<P>>` directly, no
    deep-clone. Saves bytes on the build *and* CPU on inspection paths.
    Section updated: §2.2.

### Sections of PLAN.md modified

§1 (project structure: `core/accessible.ts`, `utils/env.ts`,
`orm/*/filter.ts`, condition tagging in core comments), §2.2 (entire
`Enforcer` interface, `EnforcerOptions`, `CheckArgs`), §2.4 (adapter
naming + Workers `waitUntil`, React `useCan` object form), §2.5 (added
`accessibleBy` + filter AST), §4.1 (rewritten `RuleDef`, added
`RuleObject` with `priority`, `ConditionEntry`, `ValidatePolicy<P>`,
`definePolicy` signature, §4.1.1 condition tagging helpers), §4.3
(invariant table now references `ValidatePolicy<P>`, added `data`
narrowing row), §4.4 (call-site narrowing example, `defineCondition`
usage), §5.1 (added `ASYNC_CONDITION_IN_SYNC_PATH`, `AUDIT_FAILED`),
§5.2 (rewritten table — drop on throw, fail-secure on non-bool, audit
fail modes), §5.3 (no re-throw, monitoring example), §6.1 (ESM-only
note, ORM budgets bumped), §6.3 (drop CJS, target ES2024), §7.2 (Node
20 floor), §8.1 (target ES2024), §8.3 (no `main`, ESM-only exports,
Node 20+), §9.2 (entire subsection — additive model, deterministic
ordering, condition tagging, fail-secure semantics, exact-match cache
key), §9.3.1 (portable env probe), §9.4 (rewritten — failure modes,
`waitUntil`, no auto tenant hash), §10 (new — Out of Scope), Appendix
A (uses `defineCondition`, `enforce`, `auditFailureMode`).

### package.json modified

`engines.node` → `>=20`; `main` removed; root and `./errors` `require`
resolutions removed from `exports`; `dist/index.cjs` and
`dist/errors/index.cjs` removed from `size-limit`; `@types/node` bumped
to match Node 22 examples.
