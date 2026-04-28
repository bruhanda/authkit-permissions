import type { AccessibleByFilter } from '../../core/accessible-by.js';

/** A MongoDB / Mongoose `filter` document. */
export type MongoFilter = Record<string, unknown>;

/**
 * Translate an `AccessibleByFilter` AST to a Mongo filter document.
 *
 * `kind: 'all'` becomes `{}`. `kind: 'none'` becomes `{ _id: { $in: [] } }`,
 * which Mongo short-circuits to an empty result set.
 *
 * @param filter The AST returned by `accessibleBy()`.
 *
 * @returns A Mongo filter document.
 *
 * @throws Never throws.
 *
 * @example
 * ```ts
 * const filter = accessibleBy(ability, { resource: 'post' });
 * const docs = await Post.find(toMongo(filter));
 * ```
 */
export function toMongo(filter: AccessibleByFilter): MongoFilter {
  switch (filter.kind) {
    case 'all':
      return {};
    case 'none':
      return { _id: { $in: [] } };
    case 'eq':
      return { [filter.field]: filter.value };
    case 'in':
      return { [filter.field]: { $in: [...filter.values] } };
    case 'and':
      return { $and: filter.filters.map((f) => toMongo(f)) };
    case 'or':
      return { $or: filter.filters.map((f) => toMongo(f)) };
  }
}
