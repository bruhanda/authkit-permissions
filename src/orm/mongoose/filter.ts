import type { FilterAst } from '../../types/filter.js';

/**
 * Lower a `FilterAst` into a MongoDB query document.
 *
 * Opaque nodes are dropped (treated as match-all) — the application
 * performs a post-fetch check after `find()` resolves.
 *
 * @returns a plain object spreadable into a Mongoose `find(filter)` call.
 *
 * @example
 *   const filter = toMongoFilter(ast);
 *   await Document.find({ ...filter, archived: false });
 */
export function toMongoFilter(ast: FilterAst): Record<string, unknown> {
  switch (ast.kind) {
    case 'true':
    case 'opaque':
      return {};
    case 'false':
      // Always-false filter — `_id: null` is the conventional "no match"
      // shape for MongoDB queries that need to short-circuit.
      return { $expr: { $eq: [false, true] } };
    case 'eq':
      return { [ast.field]: ast.value };
    case 'in':
      return { [ast.field]: { $in: ast.values } };
    case 'and':
      return { $and: ast.nodes.map(toMongoFilter) };
    case 'or':
      return { $or: ast.nodes.map(toMongoFilter) };
    case 'not':
      return { $nor: [toMongoFilter(ast.node)] };
  }
}
