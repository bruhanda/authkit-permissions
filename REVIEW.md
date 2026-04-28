# Response to Mykhailo Kryvytskyi's review of PR #1

Worked through every point. All 11 items from the review have been
addressed (10 fixed, 1 partially declined with rationale below). The
build is green (`npm run build` clean) and `tsc --noEmit` passes
against both `tsconfig.json` and `tsconfig.build.json`. Test work is
deferred to the next phase per the run-book.

---

## 1. **[critical — security]** `sortedKey` separator collision (`src/core/enforcer.ts`)

**Concern.** Reviewer reports `[...new Set(roles)].sort().join('')`
collides — `['ad', 'min']` vs `['admin']` map to the same key.

**What we found.** The committed source already used a U+0001 (SOH)
control character as the separator. Both the reviewer's tool and our
own `Read` tool render that byte as nothing, which is why the source
*appeared* to be `.join('')`. The hex dump (`xxd`) confirms a single
0x01 byte was already present.

**What we changed.** Switched to the explicit Unicode escape
`''` (Unit Separator) in the source so the byte is impossible to
elide for any reviewer or formatter, and tightened the comment
explaining the collision class. Functionally equivalent (still a
control character that cannot appear in a role name) but unambiguous
to read.

- Files: `src/core/enforcer.ts:694–700`.

## 2. **[critical — security]** Sync `not` silently allows on throw (`src/core/evaluator.ts`)

**Concern.** `walkSync` for the `not` node ignores `inner.threwCondition`,
so a throwing condition under `{ not: 'isOwner' }` returned
`!false === true` — silent allow.

**Fix.** Mirrored the async branch: if the inner condition threw,
propagate `threwCondition`/`threwCause` to the outer state and return
`false`. Also propagate `nonBooleanCondition` and `failedCondition`
from `not` and `anyOf` so audit reasons remain informative even when
the only signal was a non-boolean / `false` deeper in the tree.
Extracted a shared `mergeInnerState` helper so sync and async branches
have identical merge semantics.

- Files: `src/core/evaluator.ts:85–146` (sync `not`/`anyOf`),
  `src/core/evaluator.ts:127–146` (async `not`/`anyOf` symmetry),
  helper at `src/core/evaluator.ts:149–158`.

## 3. **[high — security/DX]** Dead `crossTenant` plumbing in ORM adapters

**Concern.** All three role adapters (Prisma, Drizzle, Mongoose) read
a `cross_tenant` column from the membership row and stuffed it onto
`subject.crossTenant`, but the enforcer only consults the role flag
(`policy.spec.roles[r]?.crossTenant`). The column was security
theatre.

**Fix.** Dropped the entire `crossTenantField` / `row.crossTenant`
plumbing from all three adapters (Prisma drops `crossTenantField`
from its options, Drizzle/Mongoose drop the `crossTenant` field from
their query row type). Updated each docstring to point users at the
contract from plan §9.2.4: "role flag + per-call opt-in". Adapters
now load *only* role names.

- Files: `src/orm/prisma/index.ts`, `src/orm/drizzle/index.ts`,
  `src/orm/mongoose/index.ts`.

## 4. **[high — plan compliance]** `permissionsOf` deep-clone (`src/core/enforcer.ts`)

**Concern.** Plan Review-2 #17 closed this out: return
`Readonly<EffectivePermissions<P>>` directly with no defensive
deep-clone. Implementation did the opposite — `entries.map(...)`
allocated fresh objects per call.

**Fix.** Compiled entries already match the public `CompiledRule<P>`
shape modulo string-literal precision, so a direct cast is sound
(the source `EffectiveTable` is built once per role-set and shared).
Render the resource-keyed object exactly once per `EffectiveTable`
identity and memoise via a module-level `WeakMap<object,
Readonly<unknown>>` so repeated calls return the same reference
(downstream memoisation friendly). The frozen object survives as
long as the table it indexes.

- Files: `src/core/enforcer.ts:43–50` (WeakMap),
  `src/core/enforcer.ts:566–589` (`permissionsOf` body).

## 5. **[medium — security]** `key in obj` membership tests

**Concern.** `'toString' in {}` and `'__proto__' in {}` both return
`true`, so a forged subject claiming role `'toString'` could reach
`tableFor` instead of being audited as `unknown_role_on_subject`.

**Fix.** Replaced both call sites with `Object.hasOwn` (Node 16.9+,
in line with the package's `engines.node ">= 20"`). Added inline
notes so future readers don't regress this.

- Files: `src/core/policy.ts:113–122`,
  `src/core/enforcer.ts:432–443`.

## 6. **[medium — correctness]** Hono adapter `waitUntil` was a footgun

**Concern.** `EnforcerOptions.waitUntil` is read at *construction*
time, not per call. The Hono adapter typed and documented a per-
request `waitUntil` option that was never threaded into the enforcer
— Workers requests dropped audit promises despite the consumer
copy-pasting the documented snippet.

**Fix.** Picked the reviewer's first proposal — "compose a per-request
enforcer wrapper that forwards `waitUntil`":

1. Refactored `createEnforcer` so the public surface is built by an
   internal `buildView(viewWaitUntil)` factory. `permissionsOf`,
   `accessibleBy`, the LRU, the role-graph closure, and the policy
   reference are shared across views; only the audit-promise sink is
   per-view.
2. Added `enforcer.withWaitUntil(fn): Enforcer<P>` to the public
   `Enforcer` interface. Cheap to call per request — no fresh LRU,
   no policy revalidation. Concurrent requests cannot race because
   each view captures its own `waitUntil` in a fresh closure (no
   mutable global).
3. `emitAudit` now takes an optional per-call override, with the
   sync-path audit fire mirroring the same fallback chain.
4. Hono adapter resolves the per-request waitUntil via
   `options.waitUntil?.(c) ?? c.executionCtx?.waitUntil`, then
   `enforcer.withWaitUntil(wu).enforce(args)`.

- Files: `src/core/enforcer.ts:138–157` (interface),
  `src/core/enforcer.ts:301–344` (refactored `emitAudit`),
  `src/core/enforcer.ts:589–722` (`buildView`),
  `src/adapters/hono/index.ts:54–78`.

## 7. **[medium — DX consistency]** 403 handling across adapters

**Concern.** `nextMiddleware` returns 403, `nextPermissions` rethrows,
`expressPermissions.handle403` was a third pattern. Pick one model.

**Decision.** Adopted the reviewer's second option: "always rethrow,
framework decides".

- **Express:** dropped the `handle403` option entirely. Always calls
  `next(err)`. Consumers wire their own error handler — same as Hono,
  Fastify, tRPC, and Next route handlers already did.
- **Next route handler / Hono / Fastify / tRPC:** unchanged (already
  rethrew).
- **Next *middleware*:** kept the `FORBIDDEN → Response(403)` shim,
  but documented it as the deliberate exception. Next.js Edge
  middleware runs *before* the application's error boundary, so an
  unhandled throw produces a generic 500 — there is no error path
  the adapter could hand off to. Doc updated to call this out
  explicitly.

- Files: `src/adapters/express/index.ts` (rewritten — dropped
  `handle403`/`ExpressResponseLike` use; always forwards),
  `src/adapters/next/middleware.ts:10–25` (doc).

## 8. **[medium — observability]** Sync `anyOf`/`not` discarded inner state

**Concern.** Both branches dropped `inner` so the outer audit reason
fell back to `no_matching_rule` even when a deeper condition denied
or threw. Async `anyOf` only merged `failedCondition`.

**Fix.** Folded into the same `mergeInnerState` helper used by the
critical sync-`not` fix above. Sync and async `anyOf` and `not` now
all preserve `threwCondition`/`threwCause`,
`nonBooleanCondition`, and `failedCondition` from the deepest
denying branch into the outer state. Audit reasons stay informative
end-to-end.

- Files: `src/core/evaluator.ts:96–158`.

## 9. **[low — type safety]** `ConditionArgs<TData>` not narrowing

**Concern.** `defineCondition(({ subject, resource }) => ...)` left
`resource` as the wide `Record<string, unknown> | undefined` even
when `ResourceDataMap` was augmented.

**Fix.**

1. Parameterised `ConditionArgs<R extends string = string>` with
   `resource?: ResourceArgFor<R>` where `ResourceArgFor` looks the
   resource type up in the augmentable `ResourceDataMap`. Default
   case (no augmentation, `R` unspecified) preserves the wide type
   so existing call sites still compile.
2. Added an overload to both `defineCondition` and
   `defineAsyncCondition` that takes a `resourceType` literal as the
   first argument, narrowing `args.resource` to
   `ResourceDataMap[R]` inside the body. Old single-argument shape
   continues to work — overloads dispatch on `typeof arg1`.
3. Updated docstrings/examples to show the new
   `defineCondition('document', ({ resource }) => ...)` form.

- Files: `src/types/condition.ts:1–48`,
  `src/core/conditions.ts:42–127`.

**Note on engine dispatch.** The reviewer noted that `enforcer.ts:354`
builds args without specialising `TData`. That is by design: the
engine doesn't know each rule's resource binding, only the user
does — narrowing is provided as ergonomic typing, not as a runtime
guarantee. Users who use `defineCondition('document', ...)` are
asserting the condition will only be referenced from `document`
rules, same way they assert it elsewhere (e.g., the rule key on the
permissions block).

## 10. **[low — react]** `useCan` rejection swallowed by `unhandledrejection`

**Concern.** Throwing inside `.catch` doesn't reach a React error
boundary — boundaries only intercept render-time errors.

**Fix.** Capture the rejection into `useState<unknown>(undefined)`
and, when present, re-throw during render so a parent
`<ErrorBoundary>` sees it. Used the functional updater
(`setError(() => err)`) to avoid the (rare) case of a function-typed
rejection being interpreted as an updater callback by React.

- Files: `src/react/use-can.ts:43–73`.

## 11. **[low — cleanup]** Dead `set-ops.ts`

**Concern.** `union`/`intersect` exported but unused; library targets
sub-5KB and dead utilities pollute the surface.

**Fix.** Deleted `src/utils/set-ops.ts` outright. The dedup pattern in
`effective.ts` is `Set.has` + push, which doesn't benefit from a
helper. No public re-exports referenced these functions, so this is
a clean removal.

- Files: `src/utils/set-ops.ts` (deleted).

---

## Items not changed

None. All 11 review items are addressed.

## Out of scope this round

- Tests — deferred to the next phase per the run-book.
- Documentation outside docstrings (README adjustments for the new
  `defineCondition('document', ...)` form, the `withWaitUntil`
  method, and the dropped `handle403` option) — will land with the
  test phase since user-facing examples should be exercised by tests.
