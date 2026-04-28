# Changelog

All notable changes to `@authkit/permissions` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-28

Initial public release.

### Added

- **Core engine** (`@authkit/permissions`).
  - `definePolicy(spec)` — frozen, fully-typed policy with fail-fast validation (cycles, unknown role / resource / action / condition references, structural shape errors).
  - `createEnforcer(policy, options?)` — stateless decision engine with `check`, `checkSync`, `enforce`, `explain`, `permissionsOf`, `accessibleBy`, and per-request `withWaitUntil`.
  - `createSubject(init)` — typed `Subject` factory.
  - `defineCondition` / `defineAsyncCondition` — explicit sync/async tagging plus an optional `ConditionFilterHint` for `accessibleBy()` lowering.
  - `composeAudit(...hooks)` re-exported from the core entrypoint.
  - `EnforcerOptions`: `audit`, `auditFailureMode` (`'log'` / `'throw'` / `'deny'`), `cacheSize`, `conditions`, `strictTenant`, `waitUntil`.
- **Multi-tenant guard** as a first-class citizen. `strictTenant: true` by default; cross-tenant access requires both the role to declare `crossTenant: true` *and* `allowCrossTenant: true` per call (defence in depth).
- **Rule DSL** with `true`, `{ when }`, `{ allOf }`, `{ anyOf }`, `{ not }`, and an explicit `RuleObject.priority` so resolution order is contractual rather than dependent on object key order.
- **Wildcard matcher** for `'*'` actions on a resource.
- **LRU memoisation** of effective permission tables, keyed by sorted role-set.
- **Audit pipeline** (`@authkit/permissions/audit`).
  - `AuditEvent` with `ts`, `version`, `decision`, `reason`, `subject`, `action`, `resource`, optional `data` / `tenantId` / `crossTenant` / `conditionName` / `cause` / `grantedBy` / `durationMs`.
  - `AuditReason` taxonomy: `allowed_by_rule`, `no_matching_rule`, `no_roles`, `unknown_role_on_subject`, `tenant_required`, `tenant_mismatch`, `cross_tenant_disallowed`, `condition_failed`, `condition_threw`, `non_boolean_condition_result`, `audit_failed`.
  - `composeAudit(...hooks)`, `jsonFormatter`, `tenantHashFormatter` (FNV-1a 32-bit fingerprint for low-cardinality metric pipelines), `withTiming`.
- **Errors** (`@authkit/permissions/errors`). Single `PermissionError` class plus the frozen `ERROR_CODES`: `INVALID_POLICY`, `ROLE_CYCLE`, `UNKNOWN_ROLE`, `UNKNOWN_RESOURCE`, `UNKNOWN_ACTION`, `UNKNOWN_CONDITION`, `TENANT_REQUIRED`, `TENANT_MISMATCH`, `CONDITION_THREW`, `ASYNC_CONDITION_IN_SYNC_PATH`, `AUDIT_FAILED`, `FORBIDDEN`.
- **Builder** (`@authkit/permissions/builder`). Fluent `createPolicyBuilder()` for module-assembled policies (type inference erased at the boundary).
- **Framework adapters** (each tree-shakeable, host framework imported only structurally).
  - `@authkit/permissions/adapters/next` — `nextMiddleware`, `nextPermissions` (Route Handler wrapper).
  - `@authkit/permissions/adapters/hono` — `honoPermissions` with `c.executionCtx?.waitUntil` plumbing.
  - `@authkit/permissions/adapters/express` — `expressPermissions` (forwards `FORBIDDEN` to `next(err)`).
  - `@authkit/permissions/adapters/fastify` — `fastifyPermissions` `preHandler`.
  - `@authkit/permissions/adapters/nestjs` — `PermissionsGuard`, `@Requires()` decorator, `PermissionsModule.forRoot(enforcer)`.
  - `@authkit/permissions/adapters/trpc` — `trpcPermissions(t, enforcer, { getSubject })` factory.
- **ORM helpers**.
  - `@authkit/permissions/orm/prisma` — `createPrismaRoleAdapter`, `toPrismaWhere(FilterAst)`.
  - `@authkit/permissions/orm/drizzle` — `createDrizzleRoleAdapter`, `toDrizzleWhere(FilterAst)` returning a structural `DrizzleWhere` description.
  - `@authkit/permissions/orm/mongoose` — `createMongooseRoleAdapter`, `toMongoFilter(FilterAst)`.
  - Tiny `FilterAst` (`true` / `false` / `eq` / `in` / `and` / `or` / `not` / `opaque`) so each translator stays under ~60 LOC and apps remain ORM-agnostic.
- **React bindings** (`@authkit/permissions/react`): `PermissionProvider`, `useCan`, `<Can fallback>`, with rejections re-thrown into React's error boundary.
- **Vue 3 bindings** (`@authkit/permissions/vue`): `createPermissionsPlugin`, `useCan` composable returning a reactive `Ref<boolean>`, `<Can />` SFC with a `fallback` slot.
- **Type-level inference helpers**: `InferRoles<P>`, `InferResources<P>`, `InferActions<P, R>`, `InferConditions<P>`, `InferConditionMap<P>`, `ValidatePolicy<P>`, `EffectivePermissions<P>`, `CompiledRule<P>`. Module-augmentable `ResourceDataMap` for narrowing `data` and condition arguments.
- **Runtime targets**: Node 20+, Bun, Deno, modern browsers, Cloudflare Workers, Vercel Edge.
- **ESM only**, `sideEffects: false`, conditional subpath exports for first-class tree-shaking.
- **Bundle budget**: core ≤ 5 KB gzipped, every adapter / ORM helper ≤ 1.5 KB (enforced by `size-limit`).

[0.1.0]: https://github.com/bruhanda/authkit-permissions/releases/tag/v0.1.0
