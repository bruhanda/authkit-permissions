# `@authkit/permissions` — Architecture Plan

> Lightweight, **zero-dependency**, TypeScript-first RBAC/ABAC with a multi-tenant
> context as a first-class citizen. Targets **<5KB gzipped** for the core engine
> and runs unmodified in **Node 18+, Bun, Deno, Browser, Cloudflare Workers and
> Vercel Edge**. Optional, tree-shakeable adapters for **Next.js, Hono, Express,
> Fastify, NestJS, tRPC, React and Vue**.

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
│   │   │                            # - evaluates conditions sync/async
│   │   │                            # - emits audit events
│   │   ├── role-graph.ts            # topological order + cycle detection
│   │   │                            # - compiled once at definePolicy() time
│   │   │                            # - precomputes transitive role closure
│   │   ├── matcher.ts               # wildcard + literal action/resource match
│   │   │                            # - "*", "post:*", "*:read", "post:read"
│   │   │                            # - segment-aware glob, no regex (perf)
│   │   ├── conditions.ts            # condition registry + evaluator
│   │   │                            # - sync returns boolean, async returns Promise<boolean>
│   │   │                            # - short-circuits on any-deny
│   │   ├── effective.ts             # resolveEffectivePermissions(roles[])
│   │   │                            # - LRU memoised by role-set hash
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
│   │   ├── invariant.ts             # invariant(cond, msg, code) → throws PermissionError
│   │   ├── is-record.ts             # narrow `unknown` → Record<string, unknown>
│   │   └── set-ops.ts               # union/intersect for tiny role sets
│   │
│   ├── adapters/
│   │   ├── next/
│   │   │   ├── index.ts             # withPermissions(handler), createMiddleware()
│   │   │   └── route-handler.ts     # type-narrowed wrappers for App Router
│   │   ├── hono/
│   │   │   └── index.ts             # createHonoMiddleware(enforcer, getSubject)
│   │   ├── express/
│   │   │   └── index.ts             # createExpressMiddleware(...)
│   │   ├── fastify/
│   │   │   └── index.ts             # createFastifyPlugin(...)
│   │   ├── nestjs/
│   │   │   ├── index.ts             # PermissionsGuard, @Requires() decorator
│   │   │   └── module.ts            # PermissionsModule.forRoot()
│   │   └── trpc/
│   │       └── index.ts             # createPermissionsMiddleware<TRPC>()
│   │
│   ├── orm/
│   │   ├── prisma/
│   │   │   └── index.ts             # createPrismaRoleAdapter(prisma, schema)
│   │   ├── drizzle/
│   │   │   └── index.ts             # createDrizzleRoleAdapter(db, table)
│   │   └── mongoose/
│   │       └── index.ts             # createMongooseRoleAdapter(model)
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
  /** Audit hook called after every check (sync or async, fire-and-forget). */
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
}
```

The `Enforcer<P>` instance exposes a small, intention-revealing surface:

```ts
export interface Enforcer<P extends PolicySpec> {
  /**
   * Allow / deny decision with full type-safety on action and resource.
   * Returns a `boolean` for the synchronous fast-path (when no async condition
   * applies) or `Promise<boolean>` when the relevant rule needs to evaluate
   * an `AsyncConditionFn`. Use {@link Enforcer.checkAsync} when you always
   * want a Promise (tRPC/Next.js handlers usually do).
   */
  check<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): boolean | Promise<boolean>;

  /** Always-async variant. Recommended for I/O-bound conditions. */
  checkAsync<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<boolean>;

  /**
   * Same as {@link check} but throws {@link PermissionError} (`FORBIDDEN`)
   * on deny. Useful at API boundaries to short-circuit handlers without
   * branching.
   */
  authorize<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): void | Promise<void>;

  /**
   * Inspectable explain — returns the decision plus the rule that produced it,
   * the role it came from, and the conditions evaluated. Designed for audit
   * logs and test assertions, not for hot paths.
   */
  explain<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Decision<P, R, A> | Promise<Decision<P, R, A>>;

  /** Returns the (non-frozen, deep-cloned) effective-permission set. */
  permissionsOf(roles: ReadonlyArray<InferRoles<P>>): EffectivePermissions<P>;

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
  /** Optional resource instance for ABAC conditions (ownership, tenancy). */
  data?: ResourceData;
  /**
   * Tenant scope of the check. Defaults to `subject.tenantId`. Passing a
   * different value triggers `TENANT_MISMATCH` unless the subject has a role
   * marked `crossTenant: true` in the policy (rare, audit-flagged).
   */
  tenantId?: string;
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
`Subject`, calls `enforcer.authorize(...)`, and lets the framework handle the
thrown `PermissionError` via its own error pipeline.

#### Hono

```ts
import { createHonoMiddleware } from '@authkit/permissions/adapters/hono';

app.use(
  '/api/*',
  createHonoMiddleware(enforcer, {
    getSubject: (c) => c.var.user,                  // your auth result
    require: (c) => ({ resource: 'document', action: 'read' }),
  }),
);
```

#### Next.js (App Router)

```ts
// app/api/documents/[id]/route.ts
import { withPermissions } from '@authkit/permissions/adapters/next';

export const GET = withPermissions(
  enforcer,
  { resource: 'document', action: 'read' },
  async (req, { params, subject }) => Response.json(await load(params.id)),
);
```

#### tRPC

```ts
import { createPermissionsMiddleware } from '@authkit/permissions/adapters/trpc';

export const requires = createPermissionsMiddleware(t, enforcer);

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
const allowed = useCan('update', 'document', doc);
```

### 2.5 ORM role adapters

Out-of-the-box helpers to load `roles` and `tenantId` for a user from a typical
`memberships` table — pure functions, no decorators, no global registration.

```ts
import { createPrismaRoleAdapter } from '@authkit/permissions/orm/prisma';

const roleAdapter = createPrismaRoleAdapter(prisma, {
  membershipModel: 'membership',
  userField: 'userId',
  tenantField: 'tenantId',
  roleField: 'role',
});

const subject = await roleAdapter.loadSubject({ userId, tenantId });
```

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
  /** Allow checks across tenants. Default false. Audit-flagged when true. */
  readonly crossTenant?: boolean;
}

export interface ResourceDef<TAction extends ActionString = ActionString> {
  readonly actions: ReadonlyArray<TAction>;
  readonly description?: string;
}

export type RuleDef<TCond extends ConditionName = ConditionName> =
  | true
  | { readonly when: TCond | ReadonlyArray<TCond> }   // AND
  | { readonly anyOf: ReadonlyArray<TCond> }          // OR
  | { readonly not: TCond | RuleDef<TCond> };         // NEGATION

export type ResourcePermissions<
  R extends ResourceDef,
  TCond extends ConditionName,
> =
  | ReadonlyArray<R['actions'][number] | '*'>
  | { readonly [A in R['actions'][number]]?: RuleDef<TCond> }
  | { readonly '*'?: RuleDef<TCond> };

export interface PolicySpec {
  readonly version?: string;
  readonly roles: { readonly [R in string]: RoleDef<string> };
  readonly resources: { readonly [Res in string]: ResourceDef };
  readonly conditions?: { readonly [C in string]: ConditionFn | AsyncConditionFn };
  readonly permissions: {
    readonly [R in string]?: {
      readonly [Res in string]?: ResourcePermissions<ResourceDef, string>;
    };
  };
}

/** Result of `definePolicy(spec)`. Carries the literal `P` for inference. */
export interface Policy<P extends PolicySpec> {
  readonly spec: P;
  /** Branded so `Policy<A>` is not assignable to `Policy<B>`. */
  readonly __brand: 'authkit/policy';
}
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

| Mistake | Caught by | Diagnostic |
|---|---|---|
| `enforcer.check({ resource: 'documnt', action: 'read' })` | `R extends InferResources<P>` | `Type '"documnt"' is not assignable to type '"project" \| "document"'` |
| `enforcer.check({ resource: 'document', action: 'rea' })` | `A extends InferActions<P, R>` | `Type '"rea"' is not assignable to type '"create" \| "read" \| ...'` |
| `permissions.member.document = ['delet']` (typo) in `definePolicy` | template-literal validation in `ResourcePermissions` | `Type '"delet"' is not assignable to type '"create" \| "read" \| ...'` |
| `roles.member.extends = ['admn']` | `extends?: readonly (keyof P['roles'])[]` | `Type '"admn"' is not assignable to type '"owner" \| "admin" \| ...'` |
| Referencing missing condition `{ when: 'isOwnr' }` | `RuleDef<keyof P['conditions']>` | `Type '"isOwnr"' is not assignable to type '"isOwner" \| "sameTenant"'` |
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

…which makes `data` strongly typed inside conditions:

```ts
conditions: {
  isOwner: ({ subject, resource, resourceType }) => {
    // resourceType is narrowed to 'document' | 'project'; resource has the
    // matching shape from ResourceDataMap when passed.
    return resource?.ownerId === subject.id;
  },
};
```

---

## 5. Error Handling Strategy

### 5.1 One error class, typed codes

```ts
// errors/codes.ts
export const ERROR_CODES = {
  INVALID_POLICY:        'INVALID_POLICY',        // thrown from definePolicy
  ROLE_CYCLE:            'ROLE_CYCLE',
  UNKNOWN_ROLE:          'UNKNOWN_ROLE',
  UNKNOWN_RESOURCE:      'UNKNOWN_RESOURCE',
  UNKNOWN_ACTION:        'UNKNOWN_ACTION',
  UNKNOWN_CONDITION:     'UNKNOWN_CONDITION',
  TENANT_REQUIRED:       'TENANT_REQUIRED',       // strictTenant violation
  TENANT_MISMATCH:       'TENANT_MISMATCH',
  CONDITION_THREW:       'CONDITION_THREW',
  FORBIDDEN:             'FORBIDDEN',             // thrown by authorize()
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
| `enforcer.check` / `checkAsync` | **returns** `boolean` (or Promise of) on allow/deny | Hot path; caller decides what to do |
| `enforcer.authorize` | **throws** `PermissionError(FORBIDDEN)` on deny | Convenience for HTTP/RPC handlers |
| `enforcer.explain` | **never throws** (except for ROLE_CYCLE / UNKNOWN_*) | Designed for tests/audit |
| Condition function throws | enforcer wraps and re-throws as `CONDITION_THREW`, audit emits `denied` for this attempt with the original cause | Prevents privilege escalation through buggy conditions |
| `strictTenant: true` + missing `tenantId` | **throws** `TENANT_REQUIRED` from `check` | Tenant-leakage is a security incident, not a deny |

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

The original error then propagates so application monitoring can flag it
loudly — we never silently turn a buggy condition into a permanent deny
without telling someone.

---

## 6. Bundle & Tree-shaking Plan

Target from the report: `min_bundle_size_kb: 2.8`, `target_bundle_size_kb: 5`.

### 6.1 Entry points (subpath exports)

| Subpath | Purpose | Size budget (gzipped, minified) |
|---|---|---|
| `.` (root) | core: `definePolicy`, `createEnforcer`, types, `PermissionError` | **5 KB** |
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
| `./orm/prisma` | role/membership loader | 0.6 KB |
| `./orm/drizzle` | role/membership loader | 0.6 KB |
| `./orm/mongoose` | role/membership loader | 0.6 KB |
| `./react` | provider + hook + component | 1.2 KB |
| `./vue` | plugin + composable + component | 1 KB |

`size-limit` runs in CI with these budgets — a regression fails the PR.

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

- `format: ['esm', 'cjs']` — ESM for modern runtimes (and required by
  Workers/Edge), CJS only for the root entry to support older Node
  consumers; framework adapters are ESM-only because every supported
  framework version is ESM-compatible.
- `dts: true` — emits `.d.ts` next to JS, walks subpath entries.
- `treeshake: 'recommended'` — Rollup-flavoured shaking on top of esbuild.
- `splitting: false` — avoids hash-named common chunks that complicate
  subpath exports and break `require()` resolution.
- `target: 'es2022'` — supported by Node 18, all browsers in our matrix,
  Workers and Edge.

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
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
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
- `"exports"` enumerates every subpath listed in §6.1 with both `import` and
  (for the root + errors only) `require` resolutions.
- `"engines": { "node": ">=18" }` — Node 18 is the lowest LTS still supported
  in 2026.
- Scripts: `build`, `dev`, `test`, `test:types`, `test:coverage`, `bench`,
  `lint`, `format`, `size`, `publint`, `attw`, `release`,
  `prepublishOnly` (chains `build → publint → attw → size`).
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
   Denies and audits `reason: 'TENANT_MISMATCH'` unless the subject has a
   role with `crossTenant: true`. Audit always carries both tenant ids so
   incident response can locate the leak.
5. **Action called on resource with no rule for any of the subject's roles.**
   Denies (default-deny). Audit `reason: 'NO_MATCHING_RULE'`.
6. **Wildcard rule deny vs concrete-action allow conflict.** Default policy
   semantics: **explicit deny wins**, then explicit allow, then wildcard
   allow, then wildcard deny, then default deny. Documented prominently.
7. **Async condition resolves after sync allow already returned.** Cannot
   happen — the engine inspects whether any candidate condition is async
   (`AsyncFunction` constructor or returns a thenable when invoked) and
   promotes the entire rule's evaluation to async; it cannot return
   synchronously if any candidate is async. Tested with both `async function`
   and `() => Promise<...>` shapes.
8. **Condition throws synchronously.** Caught, wrapped as
   `CONDITION_THREW`, decision is `deny`, audit emits with `cause`, and
   the wrapped error is re-thrown to the caller of `check`.
9. **Condition returns a non-boolean.** Coerced via `Boolean(...)` and
   audit emits a dev-only warning. We never silently accept truthy strings
   as allows in production.
10. **Resource `data` undefined when condition expects it.** Each condition
    is documented to handle `data === undefined`. The default conditions
    (`sameTenant`, `isOwner`) deny when data is missing.
11. **Multiple roles producing conflicting decisions.** Resolved via the
    same allow/deny precedence as wildcard conflicts.
12. **Effective-permissions cache key collision** (theoretical). We hash
    sorted role tuple via FNV-1a over the joined string; collision
    probability for typical policies (<128 roles) is <2⁻³⁰.
13. **Race condition under high concurrency on the same Enforcer
    instance.** All caches are read-only after first compute; concurrent
    writes are idempotent (same input produces same compiled output) so
    we don't need locks. Verified with `vitest --concurrency`.

### 9.3 Runtime-portability edge cases

1. **Cloudflare Workers / Vercel Edge — no `process.env`.** We never
   reference `process` directly; behaviour flags are passed via factory
   options.
2. **Workers — no `Buffer`.** No reliance on Buffer; hashing uses simple
   string ops.
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

1. **Audit hook throws.** Caught and re-thrown only if `options.strictAudit`
   is `true`. By default we log to `console.error` (Edge-safe) and continue
   — the request must not be denied because Datadog is down.
2. **Audit hook is async.** Awaited only by `checkAsync` / `authorize`; the
   sync `check` fast-path schedules the hook via `queueMicrotask` to avoid
   making every check a Promise.
3. **High-cardinality tenant id leaking into metrics.** Default formatter
   strips `tenantId` to a `tenantHash` (8-char FNV) when the formatter
   detects integration with `console`. Opt-out via `audit/formatter`.

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

## Appendix A — Worked example (end-to-end DX)

```ts
// policy.ts
import { definePolicy } from '@authkit/permissions';

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
    isOwner:    ({ subject, resource }) => resource?.ownerId === subject.id,
    sameTenant: ({ subject, resource }) => resource?.tenantId === subject.tenantId,
  },
  permissions: {
    viewer: {
      project:  ['read'],
      document: ['read', 'comment'],
    },
    member: {
      document: {
        create: { when: 'sameTenant' },
        update: { when: ['isOwner', 'sameTenant'] },
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
});

// any handler
import { enforcer } from './enforcer';

await enforcer.authorize({
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
