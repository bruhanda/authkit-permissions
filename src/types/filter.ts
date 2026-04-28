/**
 * Normalised filter AST emitted by `accessibleBy()` and consumed by the
 * per-ORM translators (`toPrismaWhere`, `toDrizzleWhere`, `toMongoFilter`).
 *
 * Intentionally tiny — `field/op/value` leaves plus the standard boolean
 * combinators — so each translator stays under ~60 LOC and application
 * code remains ORM-agnostic.
 *
 * Conditions that cannot be expressed as a filter (arbitrary lambdas with
 * no field hint) lower to `{ kind: 'opaque', conditionName }`. Translators
 * are expected to treat opaque nodes as match-all and the application
 * performs a post-fetch check against the loaded rows.
 */
export type FilterAst =
  | { readonly kind: 'true' }
  | { readonly kind: 'false' }
  | { readonly kind: 'eq'; readonly field: string; readonly value: unknown }
  | { readonly kind: 'in'; readonly field: string; readonly values: ReadonlyArray<unknown> }
  | { readonly kind: 'and'; readonly nodes: ReadonlyArray<FilterAst> }
  | { readonly kind: 'or'; readonly nodes: ReadonlyArray<FilterAst> }
  | { readonly kind: 'not'; readonly node: FilterAst }
  | { readonly kind: 'opaque'; readonly conditionName: string };
