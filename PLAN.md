# `@authkit/permissions` — Architecture Plan

> Lightweight, zero-dependency, TypeScript-first RBAC/ABAC with first-class
> multi-tenant context. Targets `<5KB` gzipped core, runs unchanged in
> Node 18+, browsers, Bun, Deno, Cloudflare Workers and Vercel Edge.

This document is the source of truth for the implementation. It describes
the project layout, the public API, internal modules, type system,
error model, bundle/tree-shaking strategy, dependencies, configuration
and edge cases. Implementation source is intentionally NOT included
here — only the contract.

---

## 1. Project Structure

```
authkit-permissions/
├── package.json                     # Public manifest + subpath exports
├── PLAN.md                          # This document
├── README.md                        # Public-facing introduction
├── LICENSE                          # MIT
├── .gitignore
├── .npmignore
├── tsconfig.json                    # Strict TS config (used by editors)
├── tsconfig.build.json              # Emit-only config for tsup
├── tsup.config.ts                   # Multi-entry ESM/CJS build
├── vitest.config.ts                 # Unit + type tests
├── vitest.workspace.ts              # Workspaces: core, adapters, types
├── biome.json                       # Lint + format (zero-dep, fast)
├── size-limit.json                  # Per-entry bundle budgets (CI-enforced)
├── .changeset/                      # Versioning workflow
├── benchmarks/
│   └── perf.bench.ts                # `vitest bench` — check throughput
├── examples/
│   ├── nextjs-app-router/           # Showcase Route-Handlers + middleware
│   ├── hono-edge/                   # Cloudflare Worker example
│   ├── trpc-server/                 # tRPC procedure middleware
│   └── react-spa/                   # `<Can/>` + `useCan()` demo
├── docs/                            # MD docs published to website later
│   ├── getting-started.md
│   ├── policy-dsl.md
│   ├── multi-tenant.md
│   ├── conditions.md
│   ├── adapters.md
│   ├── audit-and-compliance.md
│   └── migration-from-casl.md
├── src/
│   ├── index.ts                     # Public barrel for the core entry
│   │
│   ├── core/                        # Pure, runtime-agnostic kernel
│   │   ├── define-policy.ts         # `definePolicy()` constructor
│   │   ├── permissions.ts           # Returned `Permissions<T>` object
│   │   ├── ability.ts               # `abilityFor(subject)` scoped checker
│   │   ├── builder.ts               # Imperative `AbilityBuilder` (advanced)
│   │   ├── evaluator.ts             # Decision engine (deny-overrides)
│   │   ├── matcher.ts               # Wildcard / list / exact matching
│   │   ├── role-graph.ts            # Topological sort + cycle detection
│   │   ├── condition.ts             # Sync/async condition adapter
│   │   ├── tenant.ts                # First-class tenant guard
│   │   ├── decision.ts              # `Decision` factory + reason codes
│   │   └── freeze.ts                # `deepFreeze()` — policy immutability
│   │
│   ├── audit/                       # Optional logging hooks
│   │   ├── index.ts                 # Public re-export
│   │   ├── hook.ts                  # `AuditHook` contract
│   │   └── presets.ts               # `consoleAudit()`, `noopAudit()`
│   │
│   ├── errors/                      # Error model
│   │   ├── index.ts
│   │   ├── codes.ts                 # `ErrorCode` const enum
│   │   ├── permission-error.ts      # Thrown by `enforce()`
│   │   ├── policy-error.ts          # Thrown at `definePolicy()` time
│   │   └── tenant-mismatch-error.ts # Thrown when tenant guard trips
│   │
│   ├── types/                       # Pure types — zero runtime
│   │   ├── index.ts                 # Re-export of all public types
│   │   ├── policy.ts                # PolicyDefinition / Rule / RoleDef
│   │   ├── subject.ts               # `Subject<TRole>` shape
│   │   ├── decision.ts              # Decision + Reason
│   │   ├── condition.ts             # ConditionFn signatures
│   │   ├── inference.ts             # InferRoles / InferResources / InferActions
│   │   └── check-args.ts            # CheckArgs<T, R, A> conditional type
│   │
│   ├── utils/                       # Internal-only helpers (not exported)
│   │   ├── invariant.ts             # `invariant(cond, code, msg)`
│   │   ├── memoize.ts               # WeakMap-backed memo for ability()
│   │   ├── set-ops.ts               # union / intersection (Set polyfilled)
│   │   └── normalize.ts             # Normalize rule.role/resource/action to arrays
│   │
│   ├── adapters/                    # Each adapter is its own entry
│   │   ├── next/
│   │   │   ├── index.ts             # Public barrel
│   │   │   ├── middleware.ts        # `withPermissions()` for App Router
│   │   │   └── route-handler.ts     # `protectRoute()` wrapper
│   │   ├── hono/
│   │   │   └── index.ts             # `honoPermissions({permissions})`
│   │   ├── express/
│   │   │   └── index.ts             # `expressPermissions()` middleware factory
│   │   ├── fastify/
│   │   │   └── index.ts             # Fastify plugin (`fastifyPermissions`)
│   │   ├── nestjs/
│   │   │   ├── index.ts
│   │   │   ├── permissions.guard.ts # `PermissionsGuard`
│   │   │   ├── permissions.module.ts# `PermissionsModule.forRoot()`
│   │   │   └── decorators.ts        # `@RequirePermission(...)`
│   │   └── trpc/
│   │       └── index.ts             # `createProtectedProcedure()` factory
│   │
│   ├── react/                       # React 18+ adapter
│   │   ├── index.ts
│   │   ├── permissions-provider.tsx # `<PermissionsProvider/>` (Context)
│   │   ├── use-can.ts               # `useCan()` hook
│   │   └── can.tsx                  # `<Can/>` component
│   │
│   └── vue/                         # Vue 3 adapter
│       ├── index.ts
│       ├── plugin.ts                # `createPermissionsPlugin()`
│       ├── use-can.ts               # `useCan()` composable
│       └── can.ts                   # `<Can/>` functional component (h())
│
└── tests/
    ├── core/
    │   ├── define-policy.test.ts
    │   ├── role-hierarchy.test.ts   # extends, multi-inherit, cycles
    │   ├── matcher.test.ts          # wildcards, arrays
    │   ├── evaluator.test.ts        # deny-overrides, no-match
    │   ├── condition-sync.test.ts
    │   ├── condition-async.test.ts
    │   ├── tenant-isolation.test.ts # cross-tenant attempts always deny
    │   ├── ability.test.ts          # scoped ability + caching
    │   └── builder.test.ts
    ├── audit/
    │   └── hook.test.ts
    ├── errors/
    │   └── error-shapes.test.ts
    ├── types/
    │   ├── inference.test-d.ts      # `vitest --typecheck`
    │   ├── check-args.test-d.ts
    │   └── adapter-types.test-d.ts
    ├── adapters/
    │   ├── next.test.ts
    │   ├── hono.test.ts
    │   ├── express.test.ts
    │   ├── fastify.test.ts
    │   ├── nestjs.test.ts
    │   └── trpc.test.ts
    ├── react/
    │   ├── use-can.test.tsx
    │   └── can.test.tsx
    ├── vue/
    │   └── use-can.test.ts
    └── e2e/
        ├── multi-tenant-saas.test.ts
        ├── role-inheritance-real.test.ts
        ├── compliance-audit.test.ts
        └── edge-runtime-smoke.test.ts # Runs in `@cloudflare/vitest-pool-workers`
```

**Why this layout:**

- `src/core` is **pure and runtime-agnostic** — no Node APIs (`process`, `fs`,
  `Buffer`), no DOM, no React. Anything that needs a host (Express, React,
  fetch) lives behind `src/adapters` or `src/react|vue`. This is what lets
  the core run unchanged on Cloudflare Workers and Vercel Edge.
- Each adapter has its own subpath export (see §6). A consumer who imports
  `@authkit/permissions` never pays for `react`, `next`, `nestjs`, etc.
- `src/types` is isolated so `import type {...}` paths never drag runtime in.
- `src/utils` is **internal**: utilities are not re-exported from the public
  barrel, so we can refactor them freely without semver impact.

---

## 2. Public API Design

### 2.1 `definePolicy()` — the entry point

```ts
/**
 * Define an immutable, type-inferable RBAC/ABAC policy.
 *
 * The returned `Permissions` object exposes type-safe `check`, `can`,
 * `enforce`, `abilityFor` and helpers. All actions/resources/roles
 * referenced anywhere in this library are **inferred from the policy
 * literal you pass here** — there is no string-typed escape hatch.
 *
 * @typeParam TPolicy The literal type of the policy. To get full
 *                    inference, pass the policy as an object literal
 *                    OR use `as const satisfies PolicyDefinition`.
 *
 * @param policy The policy definition. Frozen with `Object.freeze`
 *               recursively at construction time — mutating the input
 *               object after `definePolicy()` returns is a no-op.
 *
 * @returns A `Permissions<TPolicy>` instance. Cheap to create
 *          (single pass over rules), safe to keep as a module-level
 *          singleton.
 *
 * @throws {PolicyError} `INVALID_POLICY` if the shape is malformed,
 *                      `CYCLE_DETECTED` if `roles[*].extends` forms a
 *                      cycle, `UNKNOWN_ROLE`/`UNKNOWN_RESOURCE`/
 *                      `UNKNOWN_ACTION` if a rule references something
 *                      not declared in `roles`/`resources`.
 *
 * @example
 * ```ts
 * import { definePolicy } from '@authkit/permissions';
 *
 * export const permissions = definePolicy({
 *   roles: {
 *     owner:  { extends: ['admin']  },
 *     admin:  { extends: ['member'] },
 *     member: { extends: ['viewer'] },
 *     viewer: {},
 *   },
 *   resources: {
 *     post:    { actions: ['read', 'create', 'update', 'delete', 'publish'] },
 *     comment: { actions: ['read', 'create', 'delete'] },
 *     billing: { actions: ['read', 'manage'] },
 *   },
 *   rules: [
 *     { role: 'viewer', resource: 'post',    action: 'read' },
 *     { role: 'member', resource: 'post',    action: ['create'] },
 *     { role: 'admin',  resource: 'post',    action: '*' },
 *     { role: 'owner',  resource: 'billing', action: 'manage' },
 *     {
 *       role: 'member', resource: 'post', action: ['update', 'delete'],
 *       condition: ({ subject, resource }) =>
 *         resource?.authorId === subject.id,
 *     },
 *   ],
 * });
 * ```
 */
export declare function definePolicy<const TPolicy extends PolicyDefinition>(
  policy: TPolicy
): Permissions<TPolicy>;
```

> The `const` modifier on the type parameter (`<const TPolicy>`) preserves
> literal narrowing without requiring the caller to write `as const`.
> This is the single most important type-system trick in the library.

### 2.2 `Permissions<T>` — the returned object

```ts
export interface Permissions<TPolicy extends PolicyDefinition> {
  /**
   * Synchronous permission check. Returns a fully-described `Decision`.
   *
   * `action` is constrained at compile time to the actions declared on the
   * supplied `resource` — `check({ resource: 'post', action: 'foo' })`
   * is a TS error.
   *
   * Use this when the caller expects a structured result (logging,
   * field-filtering, returning `403` with a reason).
   */
  check<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A>): Decision;

  /**
   * Async variant. Use when at least one applicable rule has an
   * `async` condition (e.g. DB lookup of membership).
   *
   * Synchronous rules short-circuit before any `await`, so calling
   * `checkAsync` on a sync-only path costs one microtask, not a DB hit.
   */
  checkAsync<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A>): Promise<Decision>;

  /** Sugar over `check(...).allowed`. */
  can<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A>): boolean;

  /** Sugar over `!check(...).allowed`. */
  cannot<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A>): boolean;

  /**
   * Throws `PermissionError` if denied. Convenient inside framework
   * adapters where you want a thrown failure that maps to `403`.
   *
   * @throws {PermissionError}
   */
  enforce<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A>): void;

  /**
   * Returns a `ScopedAbility` bound to a given subject. Use inside
   * request handlers to avoid passing `subject` to every check, and to
   * enable per-request memoization (the same `subject` evaluated twice
   * for the same `(resource, action)` reuses the cached decision —
   * conditions excluded).
   */
  abilityFor(
    subject: Subject<InferRoles<TPolicy>>,
  ): ScopedAbility<TPolicy>;

  /**
   * Stable JSON serialization of the policy. Roles, resources and rules
   * are emitted; **conditions are dropped** (they are functions and not
   * portable). Useful for shipping the policy to the client for UI
   * gating, or to a SOC2 auditor.
   */
  serialize(): SerializedPolicy;

  /** Returns a new `Permissions` with the audit hook attached. Original is unchanged. */
  withAudit(hook: AuditHook): Permissions<TPolicy>;

  /** Read-only access to the frozen, normalized policy (debugging/tests). */
  readonly policy: Readonly<TPolicy>;
}
```

### 2.3 `ScopedAbility<T>` — per-subject convenience

```ts
export interface ScopedAbility<TPolicy extends PolicyDefinition> {
  readonly subject: Subject<InferRoles<TPolicy>>;

  can<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    action: A,
    resource: R,
    context?: Omit<CheckArgs<TPolicy, R, A>, 'subject' | 'action' | 'resource'>,
  ): boolean;

  cannot<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    action: A,
    resource: R,
    context?: Omit<CheckArgs<TPolicy, R, A>, 'subject' | 'action' | 'resource'>,
  ): boolean;

  /**
   * Returns the array of fields the subject is allowed to read/write
   * for the given (action, resource), or `'*'` for full access.
   * Drives field-level filtering in serializers.
   */
  fieldsFor<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    action: A,
    resource: R,
  ): readonly string[] | '*';
}
```

### 2.4 `Subject<TRole>`

```ts
/**
 * The actor performing the action. The library is opinionated about
 * `tenantId` being **required and non-empty** — multi-tenant isolation
 * is the headline feature. Single-tenant apps can pass any constant
 * (`'global'`).
 */
export interface Subject<TRole extends string = string> {
  /** Stable user identifier. Used by conditions and audit logs. */
  id: string;

  /**
   * Tenant the subject is acting on behalf of. `check()` will deny
   * with `TENANT_MISMATCH` when `resource.tenantId` is set and differs.
   * Use the literal string `'*'` to opt the subject out of tenant
   * scoping (super-admin) — this is logged in audit by default.
   */
  tenantId: string;

  /** Roles assigned to this subject *for this tenantId*. */
  roles: readonly TRole[];

  /** Optional bag for ABAC conditions (department, region, plan, ...). */
  attributes?: Readonly<Record<string, unknown>>;
}
```

### 2.5 `CheckArgs` and `Decision`

```ts
/**
 * Argument shape for `check()`/`can()`. The shape is conditional:
 * - `resource` is constrained to the policy's resource keys
 * - `action`   is constrained to that resource's actions
 * - `target`   is the *resource instance* (optional, used by conditions)
 * - `context`  is a free-form bag passed through to conditions
 */
export interface CheckArgs<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
> {
  subject: Subject<InferRoles<TPolicy>>;
  resource: R;
  action: A;
  /** The concrete resource instance (`{ id, tenantId, authorId, ... }`). */
  target?: ResourceInstance;
  /** Free-form context bag passed verbatim to condition functions. */
  context?: Readonly<Record<string, unknown>>;
}

export interface ResourceInstance {
  /** When present, enables built-in tenant-mismatch detection. */
  readonly tenantId?: string;
  readonly [k: string]: unknown;
}

export interface Decision {
  /** Final verdict. `false` means: do not perform the action. */
  readonly allowed: boolean;

  /** Why we decided this way — drives logs, error messages, debugging. */
  readonly reason: DecisionReason;

  /** The single rule that produced the verdict, if any. */
  readonly matchedRule?: Readonly<{
    role: string;
    resource: string;
    action: string;
    effect: 'allow' | 'deny';
    description?: string;
  }>;

  /** Field whitelist, if the matched rule constrains attributes. */
  readonly fields?: readonly string[];

  /** Wall-clock time of the decision (audit/perf). */
  readonly durationMs?: number;
}

export type DecisionReason =
  | 'allowed_by_rule'
  | 'denied_by_rule'
  | 'no_matching_rule'
  | 'condition_failed'
  | 'condition_threw'
  | 'tenant_mismatch'
  | 'subject_has_no_roles';
```

### 2.6 Builder (advanced / dynamic)

For dynamic policies (e.g. roles loaded from DB, plugin systems) we
expose an imperative builder:

```ts
/**
 * Imperative builder. Use only when policies cannot be expressed as
 * a static literal (e.g. plugin roles loaded at runtime). Prefer
 * `definePolicy()` whenever possible — it gives you full inference.
 */
export declare class AbilityBuilder<
  TRole extends string = string,
  TResource extends string = string,
  TAction extends string = string,
> {
  role(name: TRole, opts?: { extends?: readonly TRole[] }): this;
  resource(name: TResource, actions: readonly TAction[]): this;
  allow(role: TRole, resource: TResource | '*', action: TAction | '*'): this;
  deny(role: TRole, resource: TResource | '*', action: TAction | '*'): this;
  when(condition: ConditionFn): this; // attaches to the last rule
  build(): Permissions<PolicyDefinition<TRole, TResource, TAction>>;
}
```

### 2.7 Audit hook

```ts
/**
 * Called once per `check()`/`checkAsync()` after a decision is made.
 * Throwing inside a hook is swallowed and logged via `console.warn`
 * — audit must never break the request path.
 */
export type AuditHook = (event: AuditEvent) => void | Promise<void>;

export interface AuditEvent {
  readonly subject: Subject;
  readonly action: string;
  readonly resource: string;
  readonly target?: ResourceInstance;
  readonly tenantId: string;
  readonly decision: Decision;
  readonly timestamp: string; // ISO 8601
}

/** Built-ins. */
export declare function noopAudit(): AuditHook;
export declare function consoleAudit(opts?: { level?: 'info' | 'debug' }): AuditHook;
```

### 2.8 Adapters — DX examples

#### Next.js App Router

```ts
// app/api/posts/[id]/route.ts
import { protectRoute } from '@authkit/permissions/adapters/next';
import { permissions } from '@/lib/permissions';

export const DELETE = protectRoute(
  permissions,
  { action: 'delete', resource: 'post' },
  async (req, { params, subject }) => {
    await deletePost(params.id);
    return Response.json({ ok: true });
  },
);
```

#### Hono (Edge)

```ts
import { Hono } from 'hono';
import { honoPermissions } from '@authkit/permissions/adapters/hono';
import { permissions } from './permissions';

const app = new Hono();
app.use('*', honoPermissions({
  permissions,
  getSubject: (c) => c.get('user'),
}));
app.delete('/posts/:id', async (c) => {
  c.var.enforce({ action: 'delete', resource: 'post', target: { id: c.req.param('id') } });
  // ...
});
```

#### tRPC

```ts
import { createProtectedProcedure } from '@authkit/permissions/adapters/trpc';
const protectedProcedure = createProtectedProcedure({ permissions });

export const postRouter = t.router({
  delete: protectedProcedure
    .require({ action: 'delete', resource: 'post' })
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => deletePost(input.id)),
});
```

#### NestJS

```ts
@Controller('posts')
export class PostsController {
  @Delete(':id')
  @RequirePermission({ action: 'delete', resource: 'post' })
  @UseGuards(PermissionsGuard)
  delete(@Param('id') id: string) { /* ... */ }
}
```

#### React

```tsx
import { PermissionsProvider, useCan, Can } from '@authkit/permissions/react';

<PermissionsProvider permissions={permissions} subject={currentUser}>
  <Can action="delete" resource="post" target={post}>
    <DeleteButton/>
  </Can>
  <Can action="publish" resource="post" fallback={<UpgradeBanner/>}>
    <PublishButton/>
  </Can>
</PermissionsProvider>

const canEdit = useCan('update', 'post', { target: post }); // boolean
```

---

## 3. Internal Architecture

### 3.1 Module dependency graph (core)

```
                 +------------------+
                 |  define-policy   |
                 +--------+---------+
                          |
            +-------------+-------------+
            |             |             |
            v             v             v
      +-----+-----+ +-----+-----+ +-----+-----+
      | role-graph| |  matcher  | |  freeze   |
      +-----+-----+ +-----+-----+ +-----------+
            \             /
             \           /
              v         v
          +---+---------+--+
          |   evaluator    |  <-- pure decision engine
          +---+----+-------+
              |    |
              |    +--> condition (sync/async wrapper)
              |    +--> tenant     (cross-tenant short-circuit)
              v
          +---+---+
          | decision (Decision factory + reason codes)
          +---+---+
              |
              v
        +-----+------+
        | permissions| (check / checkAsync / can / enforce / abilityFor)
        +-----+------+
              |
              v
      +-------+--------+
      |    ability     | (subject-scoped wrapper + memoization)
      +----------------+

audit/hook   <-- attached via permissions.withAudit(); called by permissions
errors/*     <-- thrown by define-policy + permissions.enforce()
utils/*      <-- consumed by everyone, exports nothing publicly
```

Rules of dependency:

1. `core/*` may not import from `adapters/*`, `react/*`, `vue/*`, `audit/*`.
2. `adapters/*` may import from `core/*` and `errors/*` only.
3. `react/*` and `vue/*` import from `core/*`, `errors/*`, `audit/*`.
4. `types/*` has zero runtime cost — `import type` only.
5. Cycles between `core/*` modules are forbidden (lint rule).

### 3.2 Data flow — a single `check()`

```
caller                                          permissions.check
  |                                                     |
  | { subject, resource, action, target, context }      |
  +---->----+                                           |
            v                                           |
       +----+--------------+                            |
       | tenant guard      |  --(mismatch)--> Decision{ tenant_mismatch }
       +----+--------------+                            |
            |                                           |
            v                                           |
       +----+--------------+                            |
       | role-graph expand |  subject.roles -> effectiveRoles[] (with extends)
       +----+--------------+                            |
            |                                           |
            v                                           |
       +----+--------------+                            |
       | rule index lookup |  O(1) by (role, resource, action)
       +----+--------------+                            |
            |                                           |
            v                                           |
       +----+--------------+                            |
       | evaluator         |  deny-overrides + first-match-wins on allows
       |   (filters by     |                            |
       |    condition)     |                            |
       +----+--------------+                            |
            |                                           |
            v                                           |
       +----+--------------+                            |
       | decision builder  |  -> Decision               |
       +----+--------------+                            |
            |                                           |
            v                                           |
       +----+--------------+                            |
       | audit hook (opt)  |  -> fire & forget          |
       +----+--------------+                            |
            |                                           |
            v                                           |
        Decision                                        |
            +-------->--------------------------->------+
```

### 3.3 Key design patterns

- **Builder + immutability** — `definePolicy()` returns a frozen object;
  mutating helpers (`withAudit`) return new instances.
- **Strategy** — `evaluator` separates the decision algorithm from the
  rule store; we can ship `deny-overrides` (default) and add
  `allow-overrides` later behind an option without breaking callers.
- **Adapter** — every framework integration is a thin bridge that
  unwraps host-specific request shape into a `CheckArgs` and forwards
  to `permissions.enforce`.
- **Phantom types** — `Permissions<TPolicy>` carries the policy literal
  as a phantom type parameter; runtime never sees `TPolicy`, but every
  call site resolves resources/actions through it.
- **Memoization (WeakMap)** — `abilityFor(subject)` caches per-subject
  decision results keyed by `(resource, action)`; cleared automatically
  when the subject is GC'd. Conditions short-circuit memoization
  (their result depends on `target`/`context`).
- **Index-by-tuple** — at construction time we precompute a `Map` keyed
  by ``${role}|${resource}|${action}`` so lookups are O(1) instead of
  scanning the rules array.

---

## 4. Type System

### 4.1 Inference helpers

```ts
/** All role names declared in a policy literal. */
export type InferRoles<P extends PolicyDefinition> =
  keyof P['roles'] & string;

/** All resource names declared in a policy literal. */
export type InferResources<P extends PolicyDefinition> =
  keyof P['resources'] & string;

/** Actions declared on a specific resource. */
export type InferActions<
  P extends PolicyDefinition,
  R extends InferResources<P>,
> = P['resources'][R] extends { actions: readonly (infer A)[] }
  ? A & string
  : never;

/** Reverse map: `{ post: 'read'|'create'|...; comment: 'read'|... }`. */
export type ActionsByResource<P extends PolicyDefinition> = {
  [R in InferResources<P>]: InferActions<P, R>;
};
```

### 4.2 The shape contracts

```ts
export interface PolicyDefinition<
  TRole extends string = string,
  TResource extends string = string,
  TAction extends string = string,
> {
  roles:     Readonly<Record<TRole,     RoleDefinition<TRole>>>;
  resources: Readonly<Record<TResource, ResourceDefinition<TAction>>>;
  rules:     ReadonlyArray<Rule<TRole, TResource, TAction>>;
  options?:  PolicyOptions;
}

export interface RoleDefinition<TRole extends string = string> {
  description?: string;
  /** Roles this role inherits from. Order is irrelevant; cycles fail at build. */
  extends?: readonly TRole[];
}

export interface ResourceDefinition<TAction extends string = string> {
  description?: string;
  actions: readonly TAction[];
}

export interface Rule<
  TRole extends string = string,
  TResource extends string = string,
  TAction extends string = string,
> {
  role:     TRole | readonly TRole[];
  resource: TResource | readonly TResource[] | '*';
  action:   TAction | readonly TAction[] | '*';
  /** Default `'allow'`. `'deny'` overrides any allow at the same priority. */
  effect?:  'allow' | 'deny';
  condition?: ConditionFn;
  /** Optional whitelist of fields the rule covers. Surfaced as `Decision.fields`. */
  fields?:  readonly string[];
  description?: string;
}

export interface PolicyOptions {
  /** Default `'deny-overrides'`. */
  combiningAlgorithm?: 'deny-overrides' | 'allow-overrides';
  /** Default `true`. Set to `false` to allow `tenantId === ''`. */
  strictTenant?: boolean;
  /** Throw at definition time if rules reference unknown ids. Default `true`. */
  strictReferences?: boolean;
}
```

### 4.3 Condition function

```ts
export type ConditionFn<
  TSubject extends Subject = Subject,
  TTarget extends ResourceInstance = ResourceInstance,
  TCtx extends Record<string, unknown> = Record<string, unknown>,
> = (args: ConditionArgs<TSubject, TTarget, TCtx>) => boolean | Promise<boolean>;

export interface ConditionArgs<TSubject, TTarget, TCtx> {
  readonly subject: TSubject;
  readonly target?: TTarget;
  readonly context: Readonly<TCtx>;
  readonly tenantId: string;
  /** Stable monotonic clock for deterministic time-based rules in tests. */
  readonly now: () => Date;
}
```

### 4.4 Compile-time guarantees

| Mistake                                            | Rejected at compile time? |
|----------------------------------------------------|---------------------------|
| `check({ resource: 'unknown', ... })`              | ✅ never assignable to `InferResources` |
| `check({ resource: 'post', action: 'foobar' })`    | ✅ `InferActions<P,'post'>` excludes it |
| `subject.roles = ['ghost']` for unknown role       | ✅ `Subject<InferRoles<P>>` |
| `definePolicy({ rules: [{ role: 'noone', ... }] })`| ✅ `Rule<TRole, ...>` constrains it |
| Forgetting `tenantId` on a subject                 | ✅ required field |
| Wildcard string typed as `'*'`                     | ✅ literal-typed branch |
| Returning `'allow'` from a condition (instead of `boolean`) | ✅ `ConditionFn` return type |

The library ships **no string-typed escape hatches** — every public
parameter is constrained by inferred types from the policy literal.

---

## 5. Error Handling Strategy

We use a **two-track strategy**:

1. **`check()` returns a `Decision`** — never throws on a denied permission.
2. **`enforce()` throws `PermissionError`** — for adapters/handlers that
   want a `try`/`catch`-friendly failure path.

This keeps audit and field-filtering paths free of `try`/`catch` while
giving framework adapters a clean throw-and-map-to-403 ergonomic.

### 5.1 Error hierarchy

```ts
export type ErrorCode =
  | 'PERMISSION_DENIED'
  | 'TENANT_MISMATCH'
  | 'INVALID_POLICY'
  | 'CYCLE_DETECTED'
  | 'UNKNOWN_ROLE'
  | 'UNKNOWN_RESOURCE'
  | 'UNKNOWN_ACTION'
  | 'CONDITION_THREW';

export abstract class AuthkitPermissionsError extends Error {
  abstract readonly code: ErrorCode;
  /** Stable, machine-readable. Always present. */
  readonly name: string = this.constructor.name;
}

export class PermissionError extends AuthkitPermissionsError {
  readonly code: 'PERMISSION_DENIED' | 'TENANT_MISMATCH';
  readonly decision: Decision;
  readonly subject: Subject;
  readonly resource: string;
  readonly action: string;
  toResponse(): { status: 403; body: { error: string; code: ErrorCode } };
}

export class PolicyError extends AuthkitPermissionsError {
  readonly code:
    | 'INVALID_POLICY'
    | 'CYCLE_DETECTED'
    | 'UNKNOWN_ROLE'
    | 'UNKNOWN_RESOURCE'
    | 'UNKNOWN_ACTION';
  readonly path?: ReadonlyArray<string | number>; // JSON pointer-like
}

export class TenantMismatchError extends PermissionError {
  readonly code: 'TENANT_MISMATCH';
}
```

### 5.2 When to throw vs return

| Site                                          | Behaviour                                         |
|-----------------------------------------------|---------------------------------------------------|
| `definePolicy()` finds a cycle                | throw `PolicyError('CYCLE_DETECTED')`             |
| `definePolicy()` references unknown role      | throw `PolicyError('UNKNOWN_ROLE')` (strict mode) |
| `check()` finds no matching rule              | `Decision { allowed: false, reason: 'no_matching_rule' }` |
| `check()` sees cross-tenant access            | `Decision { allowed: false, reason: 'tenant_mismatch' }` |
| `enforce()` and decision is `allowed: false`  | throw `PermissionError`                            |
| Async condition rejects                       | `Decision { allowed: false, reason: 'condition_threw' }` + audit log |
| Audit hook throws                             | swallowed, logged via `console.warn` once         |
| User passes `subject.roles = []`              | `Decision { reason: 'subject_has_no_roles' }`     |

**Why this split:** authorization decisions are part of normal control
flow. Throwing on a denied decision pushes every call site into a
`try`/`catch` for non-exceptional control flow, which encourages bugs
(swallowed `catch (e) {}`, missing audit). `Decision` keeps the
information-rich verdict; `enforce()` is an opt-in shortcut.

---

## 6. Bundle & Tree-shaking Plan

### 6.1 Entry points (subpath exports)

| Entry                                       | Target gzip | Purpose                          |
|---------------------------------------------|-------------|----------------------------------|
| `@authkit/permissions`                      | < 5 KB      | Core (definePolicy + checks)     |
| `@authkit/permissions/audit`                | < 0.5 KB    | `consoleAudit`, `noopAudit`      |
| `@authkit/permissions/errors`               | < 0.4 KB    | Error classes only               |
| `@authkit/permissions/types`                | 0 KB (types)| Type-only re-exports             |
| `@authkit/permissions/adapters/next`        | < 1 KB      | Next.js App Router adapter       |
| `@authkit/permissions/adapters/hono`        | < 0.6 KB    | Hono middleware                  |
| `@authkit/permissions/adapters/express`     | < 0.6 KB    | Express middleware               |
| `@authkit/permissions/adapters/fastify`     | < 0.7 KB    | Fastify plugin                   |
| `@authkit/permissions/adapters/nestjs`      | < 1.5 KB    | Guard + decorators               |
| `@authkit/permissions/adapters/trpc`        | < 0.6 KB    | tRPC procedure factory           |
| `@authkit/permissions/react`                | < 1.2 KB    | `<Can/>`, `useCan`, Provider     |
| `@authkit/permissions/vue`                  | < 1.0 KB    | `useCan` composable + plugin     |

### 6.2 Tactics

- `"sideEffects": false` in `package.json` so bundlers can drop unused exports.
- One-export-per-file inside `core/`; the public barrel re-exports only
  what's documented. No object spreads in barrels (kills tree-shaking).
- No `class` field initializers that touch external modules at top level.
- No `process.env` reads outside of `if (process?.env?...)` guards
  (Edge runtimes don't have `process`).
- Adapters live behind subpath exports; `import { definePolicy }` from
  the root never pulls in `react`, `next`, or `nestjs`.
- Errors are tiny classes, not symbols — emoji-free `name`/`message`.
- Build with `tsup` → ESM-only (CJS shims only for `errors/` and root,
  for legacy Node tooling).
- `size-limit` checks every entry in CI on every PR.

### 6.3 Conditional exports map (target shape — see `package.json`)

```jsonc
{
  ".": {
    "types":  "./dist/index.d.ts",
    "import": "./dist/index.js",
    "require":"./dist/index.cjs"
  },
  "./adapters/next":    { "types": "./dist/adapters/next/index.d.ts",    "import": "./dist/adapters/next/index.js" },
  "./adapters/hono":    { "types": "./dist/adapters/hono/index.d.ts",    "import": "./dist/adapters/hono/index.js" },
  "./adapters/express": { "types": "./dist/adapters/express/index.d.ts", "import": "./dist/adapters/express/index.js" },
  "./adapters/fastify": { "types": "./dist/adapters/fastify/index.d.ts", "import": "./dist/adapters/fastify/index.js" },
  "./adapters/nestjs":  { "types": "./dist/adapters/nestjs/index.d.ts",  "import": "./dist/adapters/nestjs/index.js" },
  "./adapters/trpc":    { "types": "./dist/adapters/trpc/index.d.ts",    "import": "./dist/adapters/trpc/index.js" },
  "./react":            { "types": "./dist/react/index.d.ts",            "import": "./dist/react/index.js" },
  "./vue":              { "types": "./dist/vue/index.d.ts",              "import": "./dist/vue/index.js" },
  "./audit":            { "types": "./dist/audit/index.d.ts",            "import": "./dist/audit/index.js" },
  "./errors":           { "types": "./dist/errors/index.d.ts",           "import": "./dist/errors/index.js", "require": "./dist/errors/index.cjs" },
  "./types":            { "types": "./dist/types/index.d.ts" },
  "./package.json":     "./package.json"
}
```

---

## 7. Dependencies

### 7.1 Runtime dependencies — **none**

The headline differentiator is zero deps. Every algorithmic primitive
we need (Set, Map, WeakMap, Object.freeze, Promise) is part of ES2020.

| Reason a dep was rejected                                           | Replacement                                  |
|---------------------------------------------------------------------|----------------------------------------------|
| `lodash.merge`, `dequal`                                            | We don't merge user input deeply             |
| `mitt`, `nanoevents`                                                | Audit hook is a single function, not pub/sub |
| `zod`/`valibot` for policy shape                                    | We validate by hand — runtime cost <1ms; ship size <100B |
| `dataloader` for async conditions                                   | We expose a `cache?:` option on conditions; user wires their loader |
| `tslib` runtime helpers                                             | `tsconfig` `target: ES2020`, `importHelpers: false` |

### 7.2 Peer dependencies (all `optional`)

| Peer            | Version           | Used by                                  |
|-----------------|-------------------|------------------------------------------|
| `next`          | `>=13.4 <16`      | `adapters/next`                          |
| `hono`          | `>=4 <5`          | `adapters/hono`                          |
| `express`       | `>=4 <6`          | `adapters/express`                       |
| `fastify`       | `>=4 <6`          | `adapters/fastify`                       |
| `@nestjs/common`| `>=10 <12`        | `adapters/nestjs`                        |
| `@trpc/server`  | `>=11 <13`        | `adapters/trpc`                          |
| `react`         | `>=18 <20`        | `react`                                  |
| `vue`           | `>=3.4 <4`        | `vue`                                    |

All peers are marked `peerDependenciesMeta: { ..: { optional: true } }`
so installing the core never drags 10 frameworks in.

### 7.3 Dev dependencies (locked in `package.json`)

`typescript`, `tsup`, `vitest`, `@vitest/coverage-v8`, `tsd`,
`@biomejs/biome`, `size-limit`, `@size-limit/preset-small-lib`,
`@types/node`, `@types/react`, `react`, `react-dom`,
`@testing-library/react`, `vue`, `@vue/test-utils`, `hono`, `express`,
`fastify`, `next`, `@nestjs/common`, `@trpc/server`,
`@cloudflare/vitest-pool-workers`, `@changesets/cli`, `publint`,
`arethetypeswrong/cli`.

---

## 8. Configuration

### 8.1 `tsconfig.json` (strict, editor-facing)

```jsonc
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2020", "DOM"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "esModuleInterop": false,
    "skipLibCheck": true,
    "useDefineForClassFields": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "rootDir": "src",
    "outDir": "dist",
    "types": ["node"]
  },
  "include": ["src", "tests"]
}
```

### 8.2 `tsconfig.build.json`

Extends the above; `"include": ["src"]`, `"declaration": true`,
`"emitDeclarationOnly": true`. `tsup` handles the JS emit; we use `tsc`
only for `.d.ts`.

### 8.3 `tsup.config.ts` (target shape)

Multi-entry build, ESM by default, CJS only for `index` and `errors`:

```ts
export default defineConfig([
  { entry: ['src/index.ts'],                  format: ['esm', 'cjs'], dts: true, treeshake: true, splitting: false },
  { entry: ['src/audit/index.ts'],            format: ['esm'],         dts: true, treeshake: true },
  { entry: ['src/errors/index.ts'],           format: ['esm', 'cjs'],  dts: true, treeshake: true },
  { entry: ['src/types/index.ts'],            format: ['esm'],         dts: true },
  { entry: ['src/adapters/next/index.ts'],    format: ['esm'],         dts: true, external: ['next'] },
  { entry: ['src/adapters/hono/index.ts'],    format: ['esm'],         dts: true, external: ['hono'] },
  { entry: ['src/adapters/express/index.ts'], format: ['esm'],         dts: true, external: ['express'] },
  { entry: ['src/adapters/fastify/index.ts'], format: ['esm'],         dts: true, external: ['fastify'] },
  { entry: ['src/adapters/nestjs/index.ts'],  format: ['esm'],         dts: true, external: ['@nestjs/common'] },
  { entry: ['src/adapters/trpc/index.ts'],    format: ['esm'],         dts: true, external: ['@trpc/server'] },
  { entry: ['src/react/index.ts'],            format: ['esm'],         dts: true, external: ['react'] },
  { entry: ['src/vue/index.ts'],              format: ['esm'],         dts: true, external: ['vue'] },
]);
```

### 8.4 `vitest.config.ts`

`environment: 'node'`, `typecheck.enabled: true`, `coverage.thresholds`
set to `lines: 95`, `branches: 95`, `functions: 100`. Workspaces split
the suite so React/Vue/Edge-runtime tests run in their own
environments.

### 8.5 `package.json` fields

The companion `package.json` (see repo root) sets:

- `"name": "@authkit/permissions"`
- `"version": "0.1.0"`
- `"type": "module"`
- `"sideEffects": false`
- `"exports": { ... full subpath map ... }`
- `"files": ["dist", "README.md", "LICENSE"]`
- `"engines": { "node": ">=18" }`
- `"keywords"`: from the report's SEO list
- `"peerDependencies"` and `"peerDependenciesMeta"` per §7.2
- Scripts: `build`, `dev`, `test`, `test:types`, `bench`, `lint`,
  `format`, `size`, `release`, `prepublishOnly`.

---

## 9. Edge Cases (must be covered by tests)

### 9.1 Policy construction

1. **Cyclic role inheritance** — `A extends B`, `B extends A` →
   `PolicyError('CYCLE_DETECTED')` at `definePolicy()`.
2. **Diamond inheritance** — `owner extends [admin, manager]`, both
   extend `member`; `member`'s permissions counted once, not twice.
3. **Self-inheritance** — `admin extends ['admin']` → `CYCLE_DETECTED`.
4. **Unknown role/resource/action in a rule** — strict mode throws,
   non-strict warns once via `console.warn`.
5. **Empty `roles`/`resources`/`rules`** — accepted; every check
   returns `{ allowed: false, reason: 'no_matching_rule' }`.
6. **Duplicate role/resource keys** — TS literal-type semantics already
   prevent this; runtime double-checks in case of dynamic builder.
7. **Reserved literal `'*'` used as a role/resource/action name** —
   rejected with `INVALID_POLICY`.
8. **Mutating the input policy after `definePolicy()`** — silently
   ignored (deep frozen).

### 9.2 Subject

9.  **`tenantId` empty string** — denied with `tenant_mismatch` unless
    `strictTenant: false`.
10. **`tenantId === '*'`** — super-admin opt-out from tenant scoping;
    every audit event flagged with `superTenant: true`.
11. **`subject.roles = []`** — every check returns
    `{ allowed: false, reason: 'subject_has_no_roles' }` (does not throw).
12. **Role unknown to the policy in `subject.roles`** — silently dropped
    in resolution (logged via `console.warn` once per role per process).
13. **Same role listed twice in `subject.roles`** — deduped.

### 9.3 Rule semantics

14. **Wildcard action `'*'` in a rule** — matches every action declared
    on that resource (not actions on other resources).
15. **Wildcard resource `'*'`** — matches every resource for that role.
16. **Both rule arrays AND wildcards** — `action: ['read', '*']` →
    `INVALID_POLICY` (mixing is ambiguous).
17. **Allow + deny on same `(role, resource, action)`** — deny wins
    (default `deny-overrides`).
18. **Allow with `condition` returning `false`** — falls through to next
    matching rule, then to `no_matching_rule` if none allow.
19. **Allow + deny, deny has condition that returns `false`** — allow
    wins (deny didn't actually trigger).
20. **`fields: []` (empty array)** — `Decision.fields = []` (read-only
    metadata); allowed remains `true`. Field-level enforcement is the
    caller's job.

### 9.4 Conditions

21. **Sync condition called from `check()`** — runs inline.
22. **Async condition called from `check()` (sync)** — returned
    decision is `{ allowed: false, reason: 'condition_failed' }` plus a
    `console.warn` (because we cannot await). Use `checkAsync()`.
23. **Condition returns a non-boolean** — coerced via `Boolean()`; in
    dev mode (process.env.NODE_ENV !== 'production') logged as a
    correctness warning.
24. **Condition throws synchronously** — `Decision { reason:
    'condition_threw' }`; original error attached via `cause`.
25. **Async condition rejects** — same as above; the rejection is
    logged (audit) but never bubbles up.
26. **`target` undefined when condition expects it** — condition
    receives `target: undefined`; condition is responsible for
    handling. We do NOT skip the condition (would be a footgun).

### 9.5 Tenant scoping

27. **`subject.tenantId === 't1'`, `target.tenantId === 't2'`** →
    `tenant_mismatch`.
28. **`target.tenantId` undefined** → tenant guard skipped (resource is
    not tenant-scoped). Conditions still run.
29. **`subject.tenantId === '*'` (super-admin)** — guard always passes;
    audit event flagged.

### 9.6 Audit

30. **Audit hook returns a Promise** — `check()` does NOT await it
    (fire-and-forget); `checkAsync()` awaits for backpressure.
31. **Audit hook throws** — error swallowed, logged once, decision
    returned unchanged.
32. **`withAudit()` chained twice** — only the latest hook runs (or we
    document compose-style chaining). Decision: latest wins.

### 9.7 Adapters

33. **Next.js — request without subject** — adapter returns 401
    (not a permission error; `getSubject()` is the auth concern).
34. **tRPC — input refining the resource shape** — adapter exposes
    `target` from the parsed input, not the raw request.
35. **NestJS guard executed before the auth guard** — guard fails
    closed (subject undefined → 401), guidance in docs to register
    auth guard first.
36. **React `<Can>` used outside `<PermissionsProvider>`** — render
    `null` and emit a single `console.error` in dev.
37. **SSR — `useCan()` on the server** — works (no DOM access);
    Provider supplies the same `permissions` instance.
38. **Edge runtime — no `process.env`** — no code path reads it
    unconditionally; smoke test runs the core in
    `@cloudflare/vitest-pool-workers`.

### 9.8 Performance / DoS surface

39. **Policy with 10 000 rules** — index lookup is O(1); construction
    is O(N). Benchmark target: `< 5 ms` to construct, `< 20 µs` per check.
40. **Subject with 100 roles** — role-graph expansion deduped by `Set`.
41. **Adversarial role graph (deep chain `r0 → r1 → … → r999`)** —
    DFS with memoization caps at O(N) once.
42. **Audit hook that hangs (never resolves)** — `check()` does not
    await; `checkAsync()` is documented to honour user-side timeouts.

---

## 10. Documentation Plan

`docs/` will be built into a small Astro site; pages mirror the report's
talking points so search queries (`"casbin alternative lightweight"`,
`"rbac for next.js app router"`) land on dedicated pages. The plan only
records the structure here — content writing is part of implementation.

---

## 11. Out of Scope (matches report)

- Authentication (delegated to a future `@authkit/session`).
- Persistence of roles/users (we ship interfaces, not a store).
- ReBAC / Zanzibar relationship graphs (use OpenFGA for that).
- Policy-as-code DSLs (Rego/Polar) — TypeScript IS the DSL.
- A UI for editing policies (commercial niche).
