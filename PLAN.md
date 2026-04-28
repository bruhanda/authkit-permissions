# `@authkit/permissions` — Architecture Plan

> Lightweight, zero-dependency, TypeScript-first RBAC/ABAC with first-class
> multi-tenant context. Targets `<5KB` gzipped core, runs unchanged in
> Node 18+, browsers, Bun, Deno, Cloudflare Workers and Vercel Edge.

This document is the source of truth for the implementation. It describes
the project layout, the public API, internal modules, type system,
error model, bundle/tree-shaking strategy, dependencies, configuration
and edge cases. Implementation source is intentionally NOT included
here — only the contract.

A `## Review Changes` log at the bottom records every adjustment made
in response to PR review feedback.

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
│   ├── orm-filters.md               # `accessibleBy()` + Prisma/Drizzle/Mongoose
│   ├── audit-and-compliance.md
│   └── migration-from-casl.md
├── src/
│   ├── index.ts                     # Public barrel for the core entry
│   │
│   ├── core/                        # Pure, runtime-agnostic kernel
│   │   ├── define-policy.ts         # `definePolicy()` constructor
│   │   ├── permissions.ts           # Returned `Permissions<T>` object
│   │   ├── ability.ts               # `abilityFor(subject)` -> `Ability<T>`
│   │   ├── evaluator.ts             # Decision engine (precedence-aware)
│   │   ├── matcher.ts               # Wildcard / list / exact matching
│   │   ├── role-graph.ts            # Topological sort + cycle detection
│   │   ├── condition.ts             # Sync/async condition adapter
│   │   ├── tenant.ts                # First-class tenant guard (cross-tenant gated)
│   │   ├── decision.ts              # `Decision` factory + reason codes
│   │   ├── serialize.ts             # Free-function `serialize(permissions)`
│   │   ├── accessible-by.ts         # `accessibleBy(ability, resource)` filter AST
│   │   └── freeze.ts                # `deepFreeze()` — policy immutability
│   │
│   ├── builder/                     # Optional imperative builder (own subpath)
│   │   └── index.ts                 # `AbilityBuilder` (advanced/dynamic)
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
│   │   ├── audit-error.ts           # Thrown when auditFailureMode === 'throw'
│   │   └── tenant-mismatch-error.ts # Thrown when tenant guard trips
│   │
│   ├── types/                       # Pure types — zero runtime
│   │   ├── index.ts                 # Re-export of all public types
│   │   ├── policy.ts                # PolicyDefinition / Rule / RoleDef
│   │   ├── subject.ts               # `Subject<TRole>` shape
│   │   ├── decision.ts              # Decision + Reason
│   │   ├── condition.ts             # ConditionFn signatures
│   │   ├── instances.ts             # `ResourceInstanceMap` per-resource shapes
│   │   ├── inference.ts             # InferRoles / InferResources / InferActions
│   │   └── check-args.ts            # CheckArgs<T, R, A> conditional type
│   │
│   ├── utils/                       # Internal-only helpers (not exported)
│   │   ├── invariant.ts             # `invariant(cond, code, msg)`
│   │   ├── memoize.ts               # WeakMap-backed memo for ability()
│   │   ├── set-ops.ts               # union / intersection (Set polyfilled)
│   │   ├── env.ts                   # Edge-safe `isProduction()` / `isDev()`
│   │   └── normalize.ts             # Normalize rule.role/resource/action to arrays
│   │
│   ├── orm/                         # ORM/query-builder integrations (own subpaths)
│   │   ├── prisma/
│   │   │   └── index.ts             # `accessibleBy()` -> Prisma `where`
│   │   ├── drizzle/
│   │   │   └── index.ts             # `accessibleBy()` -> Drizzle SQL chunk
│   │   └── mongoose/
│   │       └── index.ts             # `accessibleBy()` -> Mongo filter doc
│   │
│   ├── adapters/                    # Each adapter is its own entry
│   │   ├── next/
│   │   │   ├── index.ts             # Public barrel
│   │   │   ├── middleware.ts        # `nextPermissions()` for App Router
│   │   │   └── route-handler.ts     # `protectRoute()` per-route helper
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
│   │       └── index.ts             # `trpcPermissions()` factory + per-procedure helper
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
    │   ├── evaluator.test.ts        # precedence, priority, no-match
    │   ├── condition-sync.test.ts
    │   ├── condition-async.test.ts
    │   ├── tenant-isolation.test.ts # cross-tenant attempts always deny
    │   ├── cross-tenant.test.ts     # `crossTenant: true` + `allowCrossTenant: true`
    │   ├── ability.test.ts          # scoped ability + caching
    │   ├── serialize.test.ts        # free-function serialize / dropped conditions
    │   └── accessible-by.test.ts    # filter AST shape, wildcard handling
    ├── builder/
    │   └── builder.test.ts
    ├── orm/
    │   ├── prisma.test.ts
    │   ├── drizzle.test.ts
    │   └── mongoose.test.ts
    ├── audit/
    │   ├── hook.test.ts
    │   └── failure-mode.test.ts     # log / throw / deny
    ├── errors/
    │   └── error-shapes.test.ts
    ├── types/
    │   ├── inference.test-d.ts      # `vitest --typecheck`
    │   ├── check-args.test-d.ts
    │   ├── rule-narrowing.test-d.ts # Rule.action narrows by Rule.resource
    │   ├── instance-typing.test-d.ts# Per-resource ConditionFn target types
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
  `@authkit/permissions` never pays for `react`, `next`, `nestjs`, ORM
  filters or the imperative builder.
- `src/builder` and `src/orm/*` live outside `core/` so they can move as
  optional subpaths without bloating the default bundle.
- `src/types` is isolated so `import type {...}` paths never drag runtime in.
- `src/utils` is **internal**: utilities are not re-exported from the public
  barrel, so we can refactor them freely without semver impact. `utils/env.ts`
  centralizes runtime-feature detection (see §6.2 for the
  `typeof process !== 'undefined'` rule).

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
 * @typeParam TInstances Optional map of resource-key -> concrete TS shape
 *                    for tightly-typed `target` parameters in conditions
 *                    and `check()` calls. Defaults to a permissive
 *                    `{ tenantId?: string; [k: string]: unknown }` per
 *                    resource. See §4.3.
 *
 * @param policy The policy definition. Frozen with `Object.freeze`
 *               recursively at construction time — mutating the input
 *               object after `definePolicy()` returns is a no-op.
 *
 * @returns A `Permissions<TPolicy, TInstances>` instance. Cheap to create
 *          (single pass over rules), safe to keep as a module-level
 *          singleton.
 *
 * @throws {PolicyError} `INVALID_POLICY` if the shape is malformed,
 *                      `CYCLE_DETECTED` if `roles[*].extends` forms a
 *                      cycle, `UNKNOWN_ROLE`/`UNKNOWN_RESOURCE`/
 *                      `UNKNOWN_ACTION` if a rule references something
 *                      not declared in `roles`/`resources`,
 *                      `EMPTY_FIELDS` if any rule has `fields: []`.
 *
 * @example
 * ```ts
 * import { definePolicy } from '@authkit/permissions';
 *
 * type Instances = { post: Post; comment: Comment; billing: BillingAccount };
 *
 * export const permissions = definePolicy<typeof policy, Instances>({
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
 *       // `target` is now narrowed to `Post` (not `ResourceInstance`).
 *       condition: ({ subject, target }) => target?.authorId === subject.id,
 *     },
 *   ],
 *   options: { precedence: 'deny', strictTenant: true },
 * } as const);
 * ```
 */
export declare function definePolicy<
  const TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(policy: TPolicy): Permissions<TPolicy, TInstances>;
```

> The `const` modifier on the type parameter (`<const TPolicy>`) preserves
> literal narrowing without requiring the caller to write `as const`.
> This is the single most important type-system trick in the library.

### 2.2 `Permissions<T>` — the returned object

The full API uses **a single object-shaped argument** (`CheckArgs`) on
every check site — `Permissions` and `Ability` agree on call shape so
there is no `(action, resource)` vs `(resource, action)` confusion to
remember.

```ts
export interface Permissions<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
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
  >(args: CheckArgs<TPolicy, R, A, TInstances>): Decision;

  /**
   * Async variant. Use when at least one applicable rule has an
   * `async` condition (e.g. DB lookup of membership).
   */
  checkAsync<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A, TInstances>): Promise<Decision>;

  /** Sugar over `check(...).allowed`. */
  can<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A, TInstances>): boolean;

  /** Sugar over `!check(...).allowed`. */
  cannot<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A, TInstances>): boolean;

  /** Throws `PermissionError` if denied. */
  enforce<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: CheckArgs<TPolicy, R, A, TInstances>): void;

  /**
   * Returns an `Ability` bound to a given subject. Use inside
   * request handlers to avoid passing `subject` to every check, and to
   * enable per-request memoization (the same `subject` evaluated twice
   * for the same `(resource, action)` reuses the cached decision —
   * conditions excluded).
   *
   * The return type is named `Ability` (not `ScopedAbility`) to match
   * the verb of the factory and CASL precedent.
   */
  abilityFor(
    subject: Subject<InferRoles<TPolicy>>,
  ): Ability<TPolicy, TInstances>;

  /** Returns a new `Permissions` with the audit hook attached. Original is unchanged. */
  withAudit(hook: AuditHook): Permissions<TPolicy, TInstances>;

  /** Read-only access to the frozen, normalized policy (debugging/tests). */
  readonly policy: Readonly<TPolicy>;
}
```

> `serialize()` is **not** an instance method — it is a free function
> exported from the root entry, `serialize(permissions)`. This lets the
> 95 % of callers who never serialize their policy tree-shake it out of
> the bundle. Conditions are still dropped from the output (server-side
> only). See §3.1.

### 2.3 `Ability<T>` — per-subject convenience (object-arg API)

`Ability<T>` mirrors `Permissions` exactly minus `subject` — same
`{ resource, action, target?, context? }` object shape on every call site.

```ts
export type AbilityCheckArgs<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
  TInstances extends ResourceInstanceMap<TPolicy>,
> = Omit<CheckArgs<TPolicy, R, A, TInstances>, 'subject'>;

export interface Ability<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  readonly subject: Subject<InferRoles<TPolicy>>;

  can<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: AbilityCheckArgs<TPolicy, R, A, TInstances>): boolean;

  cannot<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: AbilityCheckArgs<TPolicy, R, A, TInstances>): boolean;

  check<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: AbilityCheckArgs<TPolicy, R, A, TInstances>): Decision;

  /** Throws `PermissionError` if denied. */
  enforce<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: AbilityCheckArgs<TPolicy, R, A, TInstances>): void;

  /**
   * Returns the array of fields the subject is allowed to read/write
   * for the given (action, resource), or `'*'` for full access.
   */
  fieldsFor<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(args: { resource: R; action: A }): readonly string[] | '*';
}
```

> Why an object: the object shape lets us add fields (`reason`, `at`,
> `meta`) later without breaking signatures, is refactor-safe, and
> eliminates the `(action, resource)` argument-order trap (CASL
> ordering vs. accesscontrol ordering — neither is "industry standard").

### 2.4 `Subject<TRole>`

```ts
/**
 * The actor performing the action.
 *
 * `tenantId` is **optional in the type** but **required at runtime under
 * default `strictTenant: true`** (see §4.2 `PolicyOptions`). Single-tenant
 * apps set `strictTenant: false` once at policy definition time and stop
 * threading the tenant through every call.
 *
 * Cross-tenant access (super-admin) is **not expressible via a stringly
 * typed sentinel**. It requires both:
 *
 * 1. `PolicyOptions.allowCrossTenant: true` at policy-construction time
 *    (default `false` — opt-in, not opt-out).
 * 2. `subject.crossTenant === true` on the individual subject.
 *
 * Both gates must agree. This forces an intentional, code-reviewable opt-in
 * — a leaked / mirrored user-controlled string can no longer escalate
 * privileges by reaching `subject.tenantId`. Audit events for crossing
 * tenants always include `crossTenant: true` and the granting policy id.
 */
export interface Subject<TRole extends string = string> {
  /** Stable user identifier. Used by conditions and audit logs. */
  id: string;

  /**
   * Tenant the subject is acting on behalf of. Required when
   * `strictTenant: true` (default). When omitted under
   * `strictTenant: false`, the tenant guard is bypassed entirely.
   */
  tenantId?: string;

  /** Roles assigned to this subject *for this tenantId*. */
  roles: readonly TRole[];

  /**
   * Opt-in cross-tenant flag. Setting `true` is a no-op unless the policy
   * was constructed with `PolicyOptions.allowCrossTenant: true`. Even
   * then, every cross-tenant call is recorded in audit with `crossTenant: true`.
   */
  crossTenant?: true;

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
 * - `target`   is the *resource instance*, narrowed via `TInstances[R]`
 * - `context`  is a free-form bag passed through to conditions
 */
export interface CheckArgs<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  subject: Subject<InferRoles<TPolicy>>;
  resource: R;
  action: A;
  /** The concrete resource instance, typed as `TInstances[R]` (e.g. `Post`). */
  target?: TInstances[R];
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
    priority?: number;
    description?: string;
  }>;

  /** Field whitelist, if the matched rule constrains attributes. Always non-empty if present (§9.3 #20). */
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
  | 'cross_tenant_disallowed'
  | 'subject_has_no_roles';
```

### 2.6 Builder (advanced / dynamic) — separate subpath

The imperative builder is a niche escape hatch (~5 % of users) but has
mutable state and method chaining that bloat the bundle. To keep the
core under 5 KB it lives at its own subpath, **`@authkit/permissions/builder`**:

```ts
// src/builder/index.ts
import { AbilityBuilder } from '@authkit/permissions/builder';

const permissions = new AbilityBuilder()
  .role('admin', { extends: ['member'] })
  .resource('post', ['read', 'create', 'update', 'delete'])
  .allow('admin', 'post', '*')
  .deny('admin', 'post', 'delete')
  .build();
```

```ts
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
  priority(value: number): this;       // attaches to the last rule
  build(): Permissions<PolicyDefinition<TRole, TResource, TAction>>;
}
```

### 2.7 Audit hook

```ts
/**
 * Called once per `check()`/`checkAsync()` after a decision is made.
 * Behaviour when the hook throws is governed by `PolicyOptions.auditFailureMode`:
 *   - `'log'`   (default) — error swallowed, logged via `console.warn`,
 *                           decision returned unchanged. Use for UI gating.
 *   - `'throw'` — error rethrown wrapped in `AuditError`. Caller decides.
 *   - `'deny'`  — decision is forced to `{ allowed: false, reason: 'condition_threw' }`,
 *                 no exception bubbles. Strictest fail-closed mode for SOC2 shops
 *                 where a broken audit pipeline must fail the request.
 */
export type AuditHook = (event: AuditEvent) => void | Promise<void>;

export interface AuditEvent {
  readonly subject: Subject;
  readonly action: string;
  readonly resource: string;
  readonly target?: ResourceInstance;
  readonly tenantId?: string;
  readonly crossTenant?: true;
  readonly decision: Decision;
  readonly timestamp: string; // ISO 8601
}

/** Built-ins. */
export declare function noopAudit(): AuditHook;
export declare function consoleAudit(opts?: { level?: 'info' | 'debug' }): AuditHook;
```

### 2.8 Adapters — DX examples (consistent naming)

All server framework adapters expose a **`<framework>Permissions()`**
factory function for the request-level middleware. Per-route helpers
keep the verbs `protect*` / `require*`.

| Framework | Middleware factory   | Per-route helper          |
|-----------|----------------------|---------------------------|
| Next.js   | `nextPermissions()`  | `protectRoute()`          |
| Hono      | `honoPermissions()`  | `c.var.enforce(...)`      |
| Express   | `expressPermissions()` | `requirePermission()`   |
| Fastify   | `fastifyPermissions()` (plugin) | `requirePermission()` |
| NestJS    | `PermissionsModule.forRoot()` | `@RequirePermission()` + `PermissionsGuard` |
| tRPC      | `trpcPermissions()`  | `createProtectedProcedure()` |

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

const canEdit = useCan({ action: 'update', resource: 'post', target: post }); // boolean
```

### 2.9 ORM / query-builder integration — `accessibleBy()`

`accessibleBy(ability, resource)` returns a **normalized filter AST**
that adapters under `@authkit/permissions/orm/{prisma,drizzle,mongoose}`
translate to the host's native `where`. This pushes authorization into
SQL/Mongo so `findMany` returns *only* rows the subject is allowed to
see (the row-level enforcement story SOC2 actually cares about — and
the single biggest reason CASL retains users today).

```ts
// Generic AST (what `accessibleBy` returns).
export type AccessibleByFilter =
  | { kind: 'all' }                             // unconstrained
  | { kind: 'none' }                            // empty result set
  | { kind: 'and'; filters: AccessibleByFilter[] }
  | { kind: 'or';  filters: AccessibleByFilter[] }
  | { kind: 'eq';  field: string; value: unknown }
  | { kind: 'in';  field: string; values: readonly unknown[] };

export declare function accessibleBy<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  TInstances extends ResourceInstanceMap<TPolicy>,
>(
  ability: Ability<TPolicy, TInstances>,
  args: { resource: R; action?: InferActions<TPolicy, R> },
): AccessibleByFilter;
```

```ts
// @authkit/permissions/orm/prisma
import { accessibleBy } from '@authkit/permissions';
import { toPrisma } from '@authkit/permissions/orm/prisma';

const filter = toPrisma(accessibleBy(ability, { resource: 'post', action: 'read' }));
const posts  = await prisma.post.findMany({ where: filter });
```

```ts
// @authkit/permissions/orm/drizzle
import { toDrizzle } from '@authkit/permissions/orm/drizzle';
const where = toDrizzle(accessibleBy(ability, { resource: 'post' }), posts);
const rows  = await db.select().from(posts).where(where);
```

```ts
// @authkit/permissions/orm/mongoose
import { toMongo } from '@authkit/permissions/orm/mongoose';
const filter = toMongo(accessibleBy(ability, { resource: 'post' }));
const docs   = await Post.find(filter);
```

**Translation rules** (and what is NOT supported):

- Built-in tenant guard always emits `{ kind: 'eq', field: 'tenantId', value: subject.tenantId }`
  (or short-circuits to `{ kind: 'all' }` when `crossTenant: true` and `allowCrossTenant: true`).
- Conditions referencing only the subject (e.g. `target.authorId === subject.id`)
  compile to `{ kind: 'eq', field: 'authorId', value: subject.id }` via a **declarative
  condition shape** (helpers like `eq('authorId', ({subject}) => subject.id)`).
  Conditions that are arbitrary user-supplied functions are **opaque**: they are
  enforced row-by-row at evaluation time and the AST falls back to `{ kind: 'all' }`
  with a `Decision.warning` so the caller knows post-filtering is required.
- Empty intersection (deny-overrides + no allow rule) compiles to `{ kind: 'none' }`,
  which adapters translate to a SQL `false` predicate / `_id: { $in: [] }` so the
  query returns zero rows without a round trip.

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
              |    +--> tenant     (cross-tenant short-circuit, gated)
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
      +-------+--------+
              |
              v
      +-------+--------+
      | accessible-by  |  (Ability -> AccessibleByFilter AST)
      +----------------+

serialize    <-- free function in core/serialize.ts (NOT on Permissions interface)
audit/hook   <-- attached via permissions.withAudit(); called by permissions
errors/*     <-- thrown by define-policy + permissions.enforce()
utils/*      <-- consumed by everyone, exports nothing publicly
utils/env.ts <-- the ONLY module that touches `process` / `globalThis`
builder/*    <-- subpath-only; depends on core but core never imports it
orm/*        <-- subpath-only; depends on accessible-by; framework-typed
```

Rules of dependency:

1. `core/*` may not import from `adapters/*`, `react/*`, `vue/*`, `audit/*`,
   `builder/*`, `orm/*`.
2. `adapters/*` may import from `core/*` and `errors/*` only.
3. `react/*` and `vue/*` import from `core/*`, `errors/*`, `audit/*`.
4. `orm/*` may import from `core/*` and `errors/*` only.
5. `builder/*` may import from `core/*` and `errors/*` only.
6. `types/*` has zero runtime cost — `import type` only.
7. Cycles between `core/*` modules are forbidden (lint rule).
8. Direct reads of `process.env`, `globalThis.process`, etc. are
   **forbidden everywhere** outside `utils/env.ts`. A Biome rule enforces
   this; CI fails on violation.

### 3.2 Data flow — a single `check()`

```
caller                                          permissions.check
  |                                                     |
  | { subject, resource, action, target, context }      |
  +---->----+                                           |
            v                                           |
       +----+--------------+                            |
       | tenant guard      |  --(mismatch)--> Decision{ tenant_mismatch }
       |                   |  --(crossTenant + allowed)-->                   |
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
       | evaluator         |  precedence-aware (deny|allow), priority-sorted,
       |   (filters by     |  insertion-order tiebreak; conditions evaluated
       |    condition)     |  lazily.                                       |
       +----+--------------+                            |
            |                                           |
            v                                           |
       +----+--------------+                            |
       | decision builder  |  -> Decision               |
       +----+--------------+                            |
            |                                           |
            v                                           |
       +----+--------------+                            |
       | audit hook (opt)  |  -> per auditFailureMode   |
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
  rule store; we ship `precedence: 'deny'` (default) and `'allow'` behind
  the same option.
- **Adapter** — every framework integration is a thin bridge that
  unwraps host-specific request shape into a `CheckArgs` and forwards
  to `permissions.enforce`.
- **Phantom types** — `Permissions<TPolicy, TInstances>` carries the policy
  literal as a phantom type parameter; runtime never sees `TPolicy`.
- **Memoization (WeakMap)** — `abilityFor(subject)` caches per-subject
  decision results keyed by `(resource, action)`; cleared automatically
  when the subject is GC'd. Conditions short-circuit memoization.
- **Index-by-tuple** — at construction time we precompute a `Map` keyed
  by ``${role}|${resource}|${action}`` so lookups are O(1).
- **Free functions for tree-shaking** — `serialize(permissions)` and
  `accessibleBy(ability, ...)` are top-level functions, not methods, so
  bundlers strip them when unused.

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

/** Per-resource concrete instance shapes (for typed `target`). */
export type ResourceInstanceMap<P extends PolicyDefinition> = {
  [R in InferResources<P>]: ResourceInstance;
};

export type DefaultInstances<P extends PolicyDefinition> = {
  [R in InferResources<P>]: ResourceInstance;
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
  rules:     ReadonlyArray<Rule<PolicyDefinition<TRole, TResource, TAction>>>;
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

/**
 * Distributive `Rule<P>` so when `resource` is the literal `'post'`,
 * `action` is constrained to `InferActions<P, 'post'>`. This closes the
 * §4.4 "no string-typed escape hatch" promise: `{ resource: 'billing',
 * action: 'publish' }` is now a TS error if `publish` belongs to `post`.
 */
export type Rule<P extends PolicyDefinition> =
  | { [R in InferResources<P>]: RuleFor<P, R> }[InferResources<P>]
  | WildcardRule<P>;

export type RuleFor<
  P extends PolicyDefinition,
  R extends InferResources<P>,
> = {
  role:     InferRoles<P> | readonly InferRoles<P>[];
  resource: R | readonly R[];
  action:   InferActions<P, R> | readonly InferActions<P, R>[] | '*';
  /** Default `'allow'`. `'deny'` overrides any allow at the same priority. */
  effect?:  'allow' | 'deny';
  condition?: ConditionFn<Subject<InferRoles<P>>, /* target */ never>;
  /**
   * Optional whitelist of fields the rule covers. **Empty arrays are
   * rejected at construction time** with `EMPTY_FIELDS` (§9.3 #20).
   */
  fields?:  readonly [string, ...string[]];
  /**
   * Higher value wins. Ties broken by insertion order (later overrides
   * earlier within the same priority bucket). Default `0`. See §9.3 #18.
   */
  priority?: number;
  description?: string;
};

export type WildcardRule<P extends PolicyDefinition> = {
  role:     InferRoles<P> | readonly InferRoles<P>[];
  resource: '*';
  /** When `resource: '*'`, action MUST be `'*'` — narrowing per resource is undefined. */
  action:   '*';
  effect?:  'allow' | 'deny';
  condition?: ConditionFn;
  priority?: number;
  description?: string;
};

export interface PolicyOptions {
  /**
   * Conflict resolution. Renamed from XACML `combiningAlgorithm` to
   * `precedence` for accessibility (target audience: senior backend devs,
   * not policy engineers). `'deny'` = deny-overrides (default), `'allow'`
   * = allow-overrides.
   */
  precedence?: 'deny' | 'allow';

  /**
   * Default `true`. When `true`, `subject.tenantId` is required at runtime
   * and a missing/empty value yields `tenant_mismatch`. When `false`,
   * the tenant guard is bypassed entirely (single-tenant mode).
   */
  strictTenant?: boolean;

  /**
   * Default `false`. Cross-tenant access (super-admin) requires this AND
   * `subject.crossTenant === true`. With this `false`, setting
   * `crossTenant` on a subject is a no-op. See §2.4.
   */
  allowCrossTenant?: boolean;

  /**
   * Default `'log'`. Behaviour when an audit hook throws/rejects:
   *   - `'log'`   — swallow + `console.warn` once; decision unchanged.
   *   - `'throw'` — rethrow as `AuditError` (caller decides).
   *   - `'deny'`  — force the decision to `{ allowed: false, reason: 'condition_threw' }`.
   */
  auditFailureMode?: 'log' | 'throw' | 'deny';

  /** Throw at definition time if rules reference unknown ids. Default `true`. */
  strictReferences?: boolean;
}
```

### 4.3 Condition function (per-resource target typing)

```ts
export type ConditionFn<
  TSubject extends Subject = Subject,
  TTarget = ResourceInstance,
  TCtx extends Record<string, unknown> = Record<string, unknown>,
> = (args: ConditionArgs<TSubject, TTarget, TCtx>) => boolean | Promise<boolean>;

export interface ConditionArgs<TSubject, TTarget, TCtx> {
  readonly subject: TSubject;
  readonly target?: TTarget;
  readonly context: Readonly<TCtx>;
  readonly tenantId?: string;
  /** Stable monotonic clock for deterministic time-based rules in tests. */
  readonly now: () => Date;
}
```

When the consumer supplies `TInstances` to `definePolicy<TPolicy,
TInstances>`, the `target` parameter inside a rule's `condition` is
typed to `TInstances[Rule['resource']]` — so a rule with `resource: 'post'`
gets `target?: Post`, not the catch-all `ResourceInstance`. This is the
ABAC ergonomics story; conditions stop being a stringly-typed black box.

### 4.4 Compile-time guarantees

| Mistake                                                          | Rejected at compile time? |
|------------------------------------------------------------------|---------------------------|
| `check({ resource: 'unknown', ... })`                            | ✅ never assignable to `InferResources` |
| `check({ resource: 'post', action: 'foobar' })`                  | ✅ `InferActions<P,'post'>` excludes it |
| `subject.roles = ['ghost']` for unknown role                     | ✅ `Subject<InferRoles<P>>` |
| `definePolicy({ rules: [{ role: 'noone', ... }] })`              | ✅ `Rule<P>` constrains it |
| `definePolicy({ rules: [{ resource: 'billing', action: 'publish' }]})` (action belongs to `post`) | ✅ distributive `RuleFor<P, R>` (§4.2) |
| Forgetting `tenantId` on a subject under `strictTenant: true`    | ⚠ runtime — type is optional, runtime guard catches it |
| Wildcard string typed as `'*'`                                   | ✅ literal-typed branch |
| Returning `'allow'` from a condition (instead of `boolean`)      | ✅ `ConditionFn` return type |
| `target.authorId` typed as `unknown` inside a `'post'` rule's condition | ✅ `TInstances['post']` narrowed (§4.3) |
| `fields: []` at `definePolicy()` time                            | ✅ `[string, ...string[]]` non-empty tuple |

The library ships **no string-typed escape hatches** — every public
parameter is constrained by inferred types from the policy literal. The
only runtime-only check is the tenant requirement, which is opt-out via
`strictTenant: false` rather than a type-system constraint, so that
single-tenant apps can omit it cleanly.

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
  | 'CROSS_TENANT_DISALLOWED'
  | 'INVALID_POLICY'
  | 'EMPTY_FIELDS'
  | 'CYCLE_DETECTED'
  | 'UNKNOWN_ROLE'
  | 'UNKNOWN_RESOURCE'
  | 'UNKNOWN_ACTION'
  | 'CONDITION_THREW'
  | 'AUDIT_FAILED';

export abstract class AuthkitPermissionsError extends Error {
  abstract readonly code: ErrorCode;
  /** Stable, machine-readable. Always present. */
  readonly name: string = this.constructor.name;
}

export class PermissionError extends AuthkitPermissionsError {
  readonly code: 'PERMISSION_DENIED' | 'TENANT_MISMATCH' | 'CROSS_TENANT_DISALLOWED';
  readonly decision: Decision;
  readonly subject: Subject;
  readonly resource: string;
  readonly action: string;
  toResponse(): { status: 403; body: { error: string; code: ErrorCode } };
}

export class PolicyError extends AuthkitPermissionsError {
  readonly code:
    | 'INVALID_POLICY'
    | 'EMPTY_FIELDS'
    | 'CYCLE_DETECTED'
    | 'UNKNOWN_ROLE'
    | 'UNKNOWN_RESOURCE'
    | 'UNKNOWN_ACTION';
  readonly path?: ReadonlyArray<string | number>; // JSON pointer-like
}

export class TenantMismatchError extends PermissionError {
  readonly code: 'TENANT_MISMATCH' | 'CROSS_TENANT_DISALLOWED';
}

export class AuditError extends AuthkitPermissionsError {
  readonly code: 'AUDIT_FAILED';
  readonly cause: unknown;
}
```

### 5.2 When to throw vs return

| Site                                          | Behaviour                                         |
|-----------------------------------------------|---------------------------------------------------|
| `definePolicy()` finds a cycle                | throw `PolicyError('CYCLE_DETECTED')`             |
| `definePolicy()` references unknown role      | throw `PolicyError('UNKNOWN_ROLE')` (strict mode) |
| `definePolicy()` rule with `fields: []`       | throw `PolicyError('EMPTY_FIELDS')`               |
| `check()` finds no matching rule              | `Decision { allowed: false, reason: 'no_matching_rule' }` |
| `check()` sees cross-tenant access            | `Decision { allowed: false, reason: 'tenant_mismatch' }` |
| `check()` sees `crossTenant: true` without policy `allowCrossTenant: true` | `Decision { reason: 'cross_tenant_disallowed' }` |
| `enforce()` and decision is `allowed: false`  | throw `PermissionError`                            |
| Async condition rejects                       | `Decision { allowed: false, reason: 'condition_threw' }` + audit log |
| Audit hook throws (mode `'log'`)              | swallowed, logged via `console.warn` once         |
| Audit hook throws (mode `'throw'`)            | rethrown as `AuditError`                           |
| Audit hook throws (mode `'deny'`)             | decision forced to `{ allowed: false, reason: 'condition_threw' }` |
| User passes `subject.roles = []`              | `Decision { reason: 'subject_has_no_roles' }`     |

**Why this split:** authorization decisions are part of normal control
flow. Throwing on a denied decision pushes every call site into a
`try`/`catch` for non-exceptional control flow, which encourages bugs
(swallowed `catch (e) {}`, missing audit). `Decision` keeps the
information-rich verdict; `enforce()` is an opt-in shortcut.

---

## 6. Bundle & Tree-shaking Plan

### 6.1 Entry points (subpath exports)

| Entry                                       | Target gzip | Purpose                                                      |
|---------------------------------------------|-------------|--------------------------------------------------------------|
| `@authkit/permissions`                      | < 5 KB      | Core (definePolicy + checks + serialize + accessibleBy AST)  |
| `@authkit/permissions/builder`              | < 0.8 KB    | Imperative `AbilityBuilder` (advanced/dynamic, opt-in)       |
| `@authkit/permissions/audit`                | < 0.5 KB    | `consoleAudit`, `noopAudit`                                  |
| `@authkit/permissions/errors`               | < 0.4 KB    | Error classes only                                           |
| `@authkit/permissions/types`                | 0 KB (types)| Type-only re-exports                                         |
| `@authkit/permissions/orm/prisma`           | < 0.6 KB    | `toPrisma(filterAst)` adapter                                |
| `@authkit/permissions/orm/drizzle`          | < 0.6 KB    | `toDrizzle(filterAst, table)` adapter                        |
| `@authkit/permissions/orm/mongoose`         | < 0.6 KB    | `toMongo(filterAst)` adapter                                 |
| `@authkit/permissions/adapters/next`        | < 1 KB      | Next.js App Router adapter (`nextPermissions` + `protectRoute`) |
| `@authkit/permissions/adapters/hono`        | < 0.6 KB    | Hono middleware (`honoPermissions`)                          |
| `@authkit/permissions/adapters/express`     | < 0.6 KB    | Express middleware (`expressPermissions`)                    |
| `@authkit/permissions/adapters/fastify`     | < 0.7 KB    | Fastify plugin (`fastifyPermissions`)                        |
| `@authkit/permissions/adapters/nestjs`      | < 1.5 KB    | Guard + decorators                                           |
| `@authkit/permissions/adapters/trpc`        | < 0.6 KB    | tRPC procedure factory (`trpcPermissions`)                   |
| `@authkit/permissions/react`                | < 1.2 KB    | `<Can/>`, `useCan`, Provider                                 |
| `@authkit/permissions/vue`                  | < 1.0 KB    | `useCan` composable + plugin                                 |

### 6.2 Tactics

- `"sideEffects": false` in `package.json` so bundlers can drop unused exports.
- One-export-per-file inside `core/`; the public barrel re-exports only
  what's documented. No object spreads in barrels (kills tree-shaking).
- `serialize()` and `accessibleBy()` are **free functions**, not methods,
  so they tree-shake when unused (per the reviewer note: SOC2 export and
  ORM filtering are not hot paths).
- The imperative `AbilityBuilder` lives behind a separate subpath
  (`/builder`) so the 95 % of callers using `definePolicy()` literals do
  not pay for its method-chained mutable state.
- No `class` field initializers that touch external modules at top level.
- **Edge-safe runtime feature detection**. All `process.env`, `globalThis.process`,
  `Deno`, `Bun` reads go through `utils/env.ts`:
  ```ts
  // src/utils/env.ts
  export const isProduction = (): boolean =>
    typeof process !== 'undefined' && process?.env?.NODE_ENV === 'production';
  export const isDev = (): boolean => !isProduction();
  ```
  Optional chaining alone (`process?.env?.X`) does **not** protect against
  `process` being undeclared in Cloudflare Workers / Deno — it would
  throw `ReferenceError`. `typeof process !== 'undefined'` is the only
  portable check. A Biome rule (`no-restricted-syntax` for `MemberExpression[object.name='process']`
  outside `src/utils/env.ts`) enforces this; CI fails on violation. The
  edge-runtime smoke test in §9.7 #38 also exercises the dev-mode
  warning code paths to catch any sneak-through.
- Adapters live behind subpath exports; `import { definePolicy }` from
  the root never pulls in `react`, `next`, `nestjs`, ORM filters, or the builder.
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
  "./builder":          { "types": "./dist/builder/index.d.ts",          "import": "./dist/builder/index.js" },
  "./orm/prisma":       { "types": "./dist/orm/prisma/index.d.ts",       "import": "./dist/orm/prisma/index.js" },
  "./orm/drizzle":      { "types": "./dist/orm/drizzle/index.d.ts",      "import": "./dist/orm/drizzle/index.js" },
  "./orm/mongoose":     { "types": "./dist/orm/mongoose/index.d.ts",     "import": "./dist/orm/mongoose/index.js" },
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
| `@prisma/client`| `>=5 <7`          | `orm/prisma`                             |
| `drizzle-orm`   | `>=0.30 <1`       | `orm/drizzle`                            |
| `mongoose`      | `>=7 <9`          | `orm/mongoose`                           |

All peers are marked `peerDependenciesMeta: { ..: { optional: true } }`
so installing the core never drags 11 frameworks in.

### 7.3 Dev dependencies (locked in `package.json`)

`typescript`, `tsup`, `vitest`, `@vitest/coverage-v8`, `@biomejs/biome`,
`size-limit`, `@size-limit/preset-small-lib`, `@types/node`,
`@types/react`, `react`, `react-dom`, `@testing-library/react`, `vue`,
`@vue/test-utils`, `hono`, `express`, `fastify`, `next`,
`@nestjs/common`, `@trpc/server`, `@prisma/client`, `drizzle-orm`,
`mongoose`, `@cloudflare/vitest-pool-workers`, `@changesets/cli`,
`publint`, `@arethetypeswrong/cli`.

> Type tests are written as `*.test-d.ts` and run with `vitest run
> --typecheck`. We **dropped `tsd`** — Vitest's built-in type-checking
> covers the same ground, and shipping one runner is cheaper than two.

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
  { entry: ['src/builder/index.ts'],          format: ['esm'],         dts: true, treeshake: true },
  { entry: ['src/orm/prisma/index.ts'],       format: ['esm'],         dts: true, external: ['@prisma/client'] },
  { entry: ['src/orm/drizzle/index.ts'],      format: ['esm'],         dts: true, external: ['drizzle-orm'] },
  { entry: ['src/orm/mongoose/index.ts'],     format: ['esm'],         dts: true, external: ['mongoose'] },
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
- `"exports": { ... full subpath map including /builder, /orm/* ... }`
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
9. **`fields: []` (empty array)** — rejected with
   `PolicyError('EMPTY_FIELDS')` at construction time. The empty array
   is ambiguous ("all" vs "none") and was a silent-permit footgun in
   the prior design.
10. **Action declared on a different resource** — e.g.
    `{ resource: 'billing', action: 'publish' }` where `'publish'` is
    declared on `'post'` — caught at compile time by distributive
    `RuleFor<P, R>` (§4.2). Runtime double-checks in builder mode.

### 9.2 Subject

11. **`tenantId` empty string under `strictTenant: true`** — denied with
    `tenant_mismatch`.
12. **`tenantId` omitted under `strictTenant: false`** — accepted; tenant
    guard is bypassed entirely. Conditions still run.
13. **`subject.crossTenant === true` with `allowCrossTenant: false`
    (default)** — denied with `cross_tenant_disallowed`. The flag has
    no effect without the policy-level opt-in.
14. **`subject.crossTenant === true` with `allowCrossTenant: true`** —
    tenant guard bypassed; every audit event flagged with `crossTenant: true`
    plus the granting policy id.
15. **`subject.roles = []`** — every check returns
    `{ allowed: false, reason: 'subject_has_no_roles' }` (does not throw).
16. **Role unknown to the policy in `subject.roles`** — silently dropped
    in resolution (logged via `console.warn` once per role per process).
17. **Same role listed twice in `subject.roles`** — deduped.

### 9.3 Rule semantics

18. **Wildcard action `'*'` in a rule** — matches every action declared
    on that resource (not actions on other resources).
19. **Wildcard resource `'*'`** — matches every resource for that role.
20. **Both rule arrays AND wildcards** — `action: ['read', '*']` →
    `INVALID_POLICY` (mixing is ambiguous).
21. **Allow + deny on same `(role, resource, action)`** — deny wins
    when `precedence: 'deny'` (default).
22. **Rule ordering & priority** — within a `(role, resource, action)`
    tuple, the evaluator sorts by `priority` descending, ties broken by
    insertion order (later rule overrides earlier within the same
    bucket). This is documented as part of the §4.2 contract so a
    refactor that re-orders rules cannot silently change behaviour.
23. **Allow with `condition` returning `false`** — falls through to next
    matching rule (by priority then insertion order), then to
    `no_matching_rule` if none allow.
24. **Allow + deny, deny has condition that returns `false`** — allow
    wins (deny didn't actually trigger).
25. **`fields` always non-empty** — empty arrays were rejected at
    construction (#9). `Decision.fields` is therefore either
    `undefined` or non-empty.

### 9.4 Conditions

26. **Sync condition called from `check()`** — runs inline.
27. **Async condition called from `check()` (sync)** — returned
    decision is `{ allowed: false, reason: 'condition_failed' }` plus a
    `console.warn` (because we cannot await). Use `checkAsync()`.
28. **Condition returns a non-boolean** — coerced via `Boolean()`; in
    dev mode (`utils/env.isDev()`, which uses
    `typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production'`)
    logged as a correctness warning. The `typeof` guard is mandatory —
    plain optional chaining would `ReferenceError` on Cloudflare
    Workers / Deno where `process` is undeclared.
29. **Condition throws synchronously** — `Decision { reason:
    'condition_threw' }`; original error attached via `cause`.
30. **Async condition rejects** — same as above; the rejection is
    logged (audit) but never bubbles up.
31. **`target` undefined when condition expects it** — condition
    receives `target: undefined`; condition is responsible for
    handling. We do NOT skip the condition (would be a footgun).
32. **`target` typed via `TInstances`** — when a consumer supplies
    `TInstances`, the condition receives `target?: TInstances[R]`, not
    the catch-all `ResourceInstance` (§4.3).

### 9.5 Tenant scoping

33. **`subject.tenantId === 't1'`, `target.tenantId === 't2'`** →
    `tenant_mismatch` (under `strictTenant: true`).
34. **`target.tenantId` undefined** → tenant guard skipped (resource is
    not tenant-scoped). Conditions still run.
35. **`subject.crossTenant === true` and `allowCrossTenant: true`** —
    guard always passes; audit event flagged with `crossTenant: true`
    (replaces the prior `'*'` sentinel — see §2.4).

### 9.6 Audit

36. **Audit hook returns a Promise** — `check()` does NOT await it
    (fire-and-forget); `checkAsync()` awaits for backpressure.
37. **Audit hook throws / rejects** — behaviour depends on
    `auditFailureMode`:
    - `'log'` (default): swallow + `console.warn` once; decision unchanged.
    - `'throw'`: rethrow as `AuditError` (the caller — typically a
      framework adapter — converts to 5xx).
    - `'deny'`: force decision to `{ allowed: false, reason: 'condition_threw' }`.
      For SOC2 shops where a broken audit pipeline must fail closed.
38. **`withAudit()` chained twice** — only the latest hook runs (latest
    wins, documented).

### 9.7 Adapters

39. **Next.js — request without subject** — adapter returns 401
    (not a permission error; `getSubject()` is the auth concern).
40. **tRPC — input refining the resource shape** — adapter exposes
    `target` from the parsed input, not the raw request.
41. **NestJS guard executed before the auth guard** — guard fails
    closed (subject undefined → 401), guidance in docs to register
    auth guard first.
42. **React `<Can>` used outside `<PermissionsProvider>`** — render
    `null` and emit a single `console.error` in dev.
43. **SSR — `useCan()` on the server** — works (no DOM access);
    Provider supplies the same `permissions` instance.
44. **Edge runtime — no `process` global at all** — only `utils/env.ts`
    accesses `process`, and it uses
    `typeof process !== 'undefined'`. The smoke test runs the core in
    `@cloudflare/vitest-pool-workers` and explicitly exercises the
    dev-mode warning paths so any sneak-through fails CI.

### 9.8 ORM filters

45. **Subject-only condition** (e.g. `target.authorId === subject.id`) —
    `accessibleBy()` compiles via the declarative condition shape into
    `{ kind: 'eq', field: 'authorId', value: subject.id }`.
46. **Opaque condition** (arbitrary user function not using the
    declarative helpers) — `accessibleBy()` returns `{ kind: 'all' }`
    plus `Decision.warning: 'opaque_condition'` so callers know they
    must post-filter row-by-row. Documented as the trade-off; no silent
    privilege grant.
47. **Empty intersection** (deny-overrides + no allow rule) →
    `{ kind: 'none' }`; adapters translate to a falsy SQL predicate /
    `_id: { $in: [] }` so the DB returns zero rows without a round trip.
48. **`crossTenant: true`** → tenant `eq` clause omitted; query returns
    every tenant's rows. Audit event records the cross-tenant access.

### 9.9 Performance / DoS surface

49. **Policy with 10 000 rules** — index lookup is O(1); construction
    is O(N). Benchmark target: `< 5 ms` to construct, `< 20 µs` per check.
50. **Subject with 100 roles** — role-graph expansion deduped by `Set`.
51. **Adversarial role graph (deep chain `r0 → r1 → … → r999`)** —
    DFS with memoization caps at O(N) once.
52. **Audit hook that hangs (never resolves)** — `check()` does not
    await; `checkAsync()` is documented to honour user-side timeouts.

---

## 10. Documentation Plan

`docs/` will be built into a small Astro site; pages mirror the report's
talking points so search queries (`"casbin alternative lightweight"`,
`"rbac for next.js app router"`, `"row level authorization typescript"`)
land on dedicated pages. The plan only records the structure here —
content writing is part of implementation. The `orm-filters.md` page
calls out `accessibleBy()` explicitly because that is the single
biggest CASL parity feature and the row-level enforcement story SOC2
auditors expect.

---

## 11. Out of Scope (matches report)

- Authentication (delegated to a future `@authkit/session`).
- Persistence of roles/users — we ship interfaces, not a store.
  ORM filtering via `accessibleBy()` is **in scope** (the AST and the
  thin `prisma`/`drizzle`/`mongoose` translators), but the storage
  layer for roles/memberships remains the consumer's responsibility.
- ReBAC / Zanzibar relationship graphs (use OpenFGA for that).
- Policy-as-code DSLs (Rego/Polar) — TypeScript IS the DSL.
- A UI for editing policies (commercial niche).

---

## Review Changes

Log of adjustments made in response to the architecture review by
Mykhailo Kryvytskyi (PR #1). Each row references the original concern,
the resolution, and the sections of this document that were edited.

| # | Reviewer concern | Resolution | Sections touched |
|---|------------------|------------|------------------|
| 1 | **[high — security]** `tenantId === '*'` sentinel for super-admin is a privilege-escalation footgun: a leaked user-controlled string evaporates every tenant boundary. | **Agreed.** Removed the `'*'` sentinel entirely. Cross-tenant access now requires both `PolicyOptions.allowCrossTenant: true` (policy-level opt-in, default `false`) AND `subject.crossTenant === true` (subject-level boolean — not a string, code-reviewable, can't be assigned by accident from a path param). New `cross_tenant_disallowed` decision reason and `CROSS_TENANT_DISALLOWED` error code surface the disallowed case explicitly instead of silently treating it as `tenant_mismatch`. | §2.4 (rewritten); §2.5 (new reason); §4.2 `PolicyOptions.allowCrossTenant`; §5.1 new error code; §9.2 #13–#14, §9.5 #35; §11 (no change). |
| 2 | **[high — DX/API]** `Permissions.check` takes an object, `ScopedAbility.can` takes positional `(action, resource, ctx)`. Argument order trap (CASL vs. accesscontrol). | **Agreed.** Aligned both interfaces on the **same single-object call shape**. `Ability` now takes `{ resource, action, target?, context? }` everywhere — refactor-safe, lets us add fields (`reason`, `at`, `meta`) later. | §2.2 (unchanged shape); §2.3 (rewritten — was `ScopedAbility`, all positional signatures replaced with `AbilityCheckArgs`); §2.8 React `useCan` example updated to object arg. |
| 3 | **[high — competitive]** No ORM/query-builder integration. `accessibleBy()` is CASL's #1 retention feature; without it we are permanently a tier behind on row-level filtering — also where SOC2 enforcement actually lives. | **Agreed.** Added `accessibleBy(ability, { resource, action? })` returning a normalized `AccessibleByFilter` AST in `src/core/accessible-by.ts`. New thin adapters under three new subpaths: `@authkit/permissions/orm/{prisma,drizzle,mongoose}` translating the AST to native `where`. Declarative condition helpers compile to `eq`/`in` clauses; opaque user-function conditions fall back to `{ kind: 'all' }` + a warning so the caller knows to post-filter. | §1 project structure (added `core/accessible-by.ts`, `src/orm/{prisma,drizzle,mongoose}/`); §2.9 (new); §3.1 module graph + dep rules; §6.1 + §6.3 entry points and exports map; §7.2 new optional peers (`@prisma/client`, `drizzle-orm`, `mongoose`); §7.3 dev deps; §8.3 tsup entries; §9.8 (new edge cases #45–#48); §11 wording on what is in/out of scope; `package.json` exports + size-limit + peerDeps. |
| 4 | **[high — type safety]** `Rule.action` is a flat union of every action across every resource — `{ resource: 'billing', action: 'publish' }` is currently type-correct even though `publish` lives on `post`. Breaks the §4.4 "no string-typed escape hatch" promise. | **Agreed.** `Rule<P>` is now a distributive type: `{ [R in InferResources<P>]: RuleFor<P, R> }[InferResources<P>]` where `RuleFor<P, R>['action']` narrows to `InferActions<P, R>`. Wildcard rules (`resource: '*'`) require `action: '*'` — split into a separate `WildcardRule<P>` branch. Added `tests/types/rule-narrowing.test-d.ts`. | §4.2 (`Rule`/`RuleFor`/`WildcardRule` rewritten); §4.4 (added row to compile-time guarantees table); §1 added `tests/types/rule-narrowing.test-d.ts`; §9.1 #10. |
| 5 | **[high — Edge runtime]** `process?.env?.NODE_ENV` still throws `ReferenceError` in Cloudflare Workers / Deno where `process` is undeclared — optional chaining only protects against `null`/`undefined`. The §9.7 #38 smoke test will pass while real Workers blow up. | **Agreed.** Centralized all `process` access in `src/utils/env.ts` (`isProduction()`, `isDev()`) using `typeof process !== 'undefined' && process?.env?.NODE_ENV …`. Added Biome `no-restricted-syntax` rule banning direct `process.*` reads outside that file; CI fails on violation. Smoke test now explicitly exercises the dev-mode warning code paths. | §1 added `src/utils/env.ts`; §3.1 dep rule #8; §6.2 (Edge-safe runtime feature detection bullet rewritten); §9.4 #28; §9.7 #44. |
| 6 | **[medium — bundle]** `AbilityBuilder` lives in `core/` and is exported from the public barrel; the 95 % of callers using `definePolicy()` literals pay for its method-chained mutable state. Same argument applies to `serialize()`. | **Agreed.** Moved `AbilityBuilder` to its own subpath `@authkit/permissions/builder` (separate `src/builder/index.ts`, `< 0.8 KB` budget). Converted `serialize()` from a `Permissions` method to a free function `serialize(permissions)` exported from the root barrel — tree-shakes when unused. | §1 layout (`core/builder.ts` removed, `src/builder/` added; `core/serialize.ts` added); §2.2 (`serialize()` removed from interface, note explaining why); §2.6 (rewritten — subpath import); §3.1 module graph + dep rule #5; §6.1 entry table + budgets; §6.2 tactics; §6.3 exports map; §8.3 tsup; `package.json` exports + size-limit. |
| 7 | **[medium — security/compliance]** Audit hook throwing is silently swallowed. For SOC2 customers the audit log IS the compliance artifact — silently dropping events is a finding waiting to happen. | **Agreed.** Added `PolicyOptions.auditFailureMode: 'log' \| 'throw' \| 'deny'`. Default `'log'` preserves the UI-gating-friendly behaviour. `'throw'` rethrows wrapped in a new `AuditError`. `'deny'` forces the decision to `allowed: false, reason: 'condition_threw'` for fail-closed strict shops. | §2.7 (auditFailureMode option + behaviour table); §4.2 `PolicyOptions.auditFailureMode`; §5.1 (new `AuditError`, `AUDIT_FAILED` code); §5.2 (three new rows); §9.6 #37; §1 added `tests/audit/failure-mode.test.ts`. |
| 8 | **[medium — naming consistency]** Five different verb patterns for adapter middleware (`protectRoute`, `honoPermissions`, `expressPermissions`, `fastifyPermissions`, `PermissionsGuard`, `createProtectedProcedure`). | **Agreed.** Standardized on **`<framework>Permissions()`** for the request-level middleware factory across all server adapters: `nextPermissions`, `honoPermissions`, `expressPermissions`, `fastifyPermissions`, `trpcPermissions`. Reserved `protect*` / `require*` verbs for **per-route** helpers (`protectRoute`, `requirePermission`, `@RequirePermission`). NestJS keeps `PermissionsModule.forRoot()` since modules don't fit the middleware factory pattern. | §1 (`adapters/next/middleware.ts` exports `nextPermissions`; `adapters/trpc/index.ts` exports `trpcPermissions`); §2.8 (added the naming table; updated tRPC and other examples). |
| 9 | **[medium — naming]** `abilityFor(subject): ScopedAbility<T>` — factory verb says "ability", return type says "ScopedAbility". | **Agreed.** Renamed the type to `Ability<T, TInstances>` (matches CASL precedent and the verb of the factory). The `ScopedAbility` name is gone. | §2.2 (return type); §2.3 (interface name + every reference); §3.1 module graph; §1 file naming unchanged (`core/ability.ts`); cross-section terminology audit. |
| 10 | **[medium — type safety]** `ConditionFn`'s `target` is typed `ResourceInstance` regardless of which resource the rule applies to — conditions are essentially untyped. | **Agreed.** Threaded a second type parameter through `definePolicy<TPolicy, TInstances>`: `TInstances extends ResourceInstanceMap<TPolicy>` lets consumers declare per-resource shapes (e.g. `{ post: Post; comment: Comment }`). `CheckArgs<P, R, A, TInstances>` now types `target?` as `TInstances[R]`, and inside a `'post'` rule's `condition` the `target` is narrowed to `Post`. Added `tests/types/instance-typing.test-d.ts`. | §2.1 (signature + example); §2.2 (`Permissions<TPolicy, TInstances>`); §2.3 `Ability<TPolicy, TInstances>`; §2.5 (`CheckArgs` typed `target`); §4.1 (`ResourceInstanceMap`, `DefaultInstances`); §4.3 (per-resource target paragraph); §4.4 (added row); §1 added `src/types/instances.ts` + test. |
| 11 | **[medium — semantics]** Rule ordering is implicit; once you have 200 rules and a refactor reorders one of them, behaviour shifts silently. | **Agreed.** Added `Rule.priority?: number` (default `0`, higher wins) AND documented the deterministic tiebreak: ties resolved by insertion order, later rule overrides earlier within the same priority bucket. The contract is in §4.2; §9.3 #22 records it as a tested edge case. | §4.2 (added `priority` to `RuleFor` + `WildcardRule`); §2.5 `Decision.matchedRule` includes `priority`; §2.6 builder `.priority(value)` chain method; §9.3 #22; §1 added `tests/core/evaluator.test.ts` covers priority + insertion order. |
| 12 | **[low — DX]** `tenantId` is required on every call even for single-tenant apps that pass a dummy `'global'` constant. Friction for a common case. | **Agreed.** Made `Subject.tenantId?: string`. With `strictTenant: true` (default), runtime requires non-empty `tenantId`. With `strictTenant: false`, the field can be omitted entirely and the tenant guard is bypassed — single-tenant users opt out **once at policy construction time** and stop threading the dummy through every call. | §2.4 (`tenantId?: string` + the runtime requirement note); §4.4 (compile-time-vs-runtime row); §9.2 #11–#12. |
| 13 | **[low — semantics]** `fields: []` with `allowed: true` is a silent-permit footgun (every reader will misread "empty whitelist" as "all fields"). | **Agreed (chose the stricter option).** `fields` is typed as a non-empty tuple `readonly [string, ...string[]]`; empty arrays are **rejected at construction time** with `PolicyError('EMPTY_FIELDS')`. `Decision.fields` is therefore either `undefined` or non-empty. | §2.5 `Decision.fields` doc updated; §4.2 `Rule.fields` typed `[string, ...string[]]`; §4.4 row added; §5.1 new error code; §5.2 row; §9.1 #9 (replaces previous #20); §9.3 #25. |
| 14 | **[low — package.json]** `arethetypeswrong` is the unscoped name; the published package is `@arethetypeswrong/cli`. Plus `tsd` and `vitest --typecheck` overlap. | **Agreed.** Replaced `arethetypeswrong` → `@arethetypeswrong/cli` in `devDependencies`. Dropped `tsd` — `vitest run --typecheck` against the existing `*.test-d.ts` files is sufficient. | `package.json` `devDependencies`; §7.3 wording. |
| 15 | **[low — terminology]** `combiningAlgorithm: 'deny-overrides' \| 'allow-overrides'` is XACML jargon; the target audience is senior backend devs, not policy engineers. | **Agreed.** Renamed `PolicyOptions.combiningAlgorithm` → `precedence: 'deny' \| 'allow'`. Shorter, no Wikipedia tab, same semantics. The rename is breaking, but no source file shipped yet — perfect time to do it. | §3.3 (Strategy bullet); §4.2 `PolicyOptions.precedence`; §1 evaluator file comment; §9.3 #21. |

**No disagreements** — every reviewer point was actionable and the
resolutions above represent the authoritative new design.

The "What's good" callouts (multi-tenant as first-class, `<const TPolicy>`,
two-track error model, `size-limit` per entry, edge-runtime smoke test,
edge-case enumeration, `PermissionError.toResponse()`, `serialize()`
dropping conditions, ReBAC out of scope) are preserved unchanged in the
revised plan — they remain the wedge against CASL/Casbin.
