import type { FilterAst } from '../../types/filter.js';

/**
 * Drizzle SQL fragment built from the filter AST.
 *
 * The runtime payload is a plain object describing the SQL shape; the
 * adapter consumer feeds it to `drizzle-orm` operators (`eq`, `inArray`,
 * `and`, `or`, `not`) at the call site to build the actual `where`. We
 * stay decoupled from Drizzle's symbol-tagged value types.
 */
export type DrizzleWhere =
  | { readonly kind: 'true' }
  | { readonly kind: 'false' }
  | { readonly kind: 'eq'; readonly column: string; readonly value: unknown }
  | { readonly kind: 'in'; readonly column: string; readonly values: ReadonlyArray<unknown> }
  | { readonly kind: 'and'; readonly nodes: ReadonlyArray<DrizzleWhere> }
  | { readonly kind: 'or'; readonly nodes: ReadonlyArray<DrizzleWhere> }
  | { readonly kind: 'not'; readonly node: DrizzleWhere }
  | { readonly kind: 'opaque'; readonly conditionName: string };

/**
 * Lower a `FilterAst` into a Drizzle-friendly `DrizzleWhere` description.
 *
 * Pass the result to a small helper in your codebase that maps each node
 * onto the matching `drizzle-orm` operator (`eq`, `inArray`, `and`, etc.).
 * Opaque nodes are passed through so the application can decide whether
 * to widen the query or perform a post-fetch check.
 *
 * @example
 *   const where = toDrizzleWhere(filter);
 *   const sql = applyWhere(documents, where); // your tiny helper
 */
export function toDrizzleWhere(ast: FilterAst): DrizzleWhere {
  switch (ast.kind) {
    case 'true':
      return { kind: 'true' };
    case 'false':
      return { kind: 'false' };
    case 'eq':
      return { kind: 'eq', column: ast.field, value: ast.value };
    case 'in':
      return { kind: 'in', column: ast.field, values: ast.values };
    case 'and':
      return { kind: 'and', nodes: ast.nodes.map(toDrizzleWhere) };
    case 'or':
      return { kind: 'or', nodes: ast.nodes.map(toDrizzleWhere) };
    case 'not':
      return { kind: 'not', node: toDrizzleWhere(ast.node) };
    case 'opaque':
      return { kind: 'opaque', conditionName: ast.conditionName };
  }
}
