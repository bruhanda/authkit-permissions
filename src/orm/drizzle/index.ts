import type { AccessibleByFilter } from '../../core/accessible-by.js';

/**
 * Minimal subset of the Drizzle SQL helpers we depend on. Avoids importing
 * `drizzle-orm` directly so consumers without Drizzle do not pay the
 * resolution cost.
 */
export interface DrizzleSqlBuilders {
  readonly eq: (col: unknown, value: unknown) => unknown;
  readonly inArray: (col: unknown, values: readonly unknown[]) => unknown;
  readonly and: (...conds: readonly unknown[]) => unknown;
  readonly or: (...conds: readonly unknown[]) => unknown;
  readonly sql: { raw: (str: string) => unknown };
}

/**
 * Translate an `AccessibleByFilter` AST to a Drizzle SQL chunk.
 *
 * Drizzle does not have a single conventional shape for "match nothing",
 * so `kind: 'none'` is rendered as `sql.raw('1 = 0')`, which every Drizzle
 * dialect optimises into an empty result set without a round trip.
 *
 * @param filter The AST returned by `accessibleBy()`.
 * @param table Drizzle table reference — column names are read from this object.
 * @param d Drizzle SQL builders (`eq`, `inArray`, `and`, `or`, `sql`).
 *
 * @returns A Drizzle SQL chunk safe to pass to `.where()`.
 *
 * @throws Never throws.
 *
 * @example
 * ```ts
 * import { eq, inArray, and, or, sql } from 'drizzle-orm';
 * import { toDrizzle } from '@authkit/permissions/orm/drizzle';
 *
 * const filter = accessibleBy(ability, { resource: 'post' });
 * const where = toDrizzle(filter, posts, { eq, inArray, and, or, sql });
 * const rows = await db.select().from(posts).where(where);
 * ```
 */
export function toDrizzle(
  filter: AccessibleByFilter,
  table: Record<string, unknown>,
  d: DrizzleSqlBuilders,
): unknown {
  switch (filter.kind) {
    case 'all':
      return d.sql.raw('1 = 1');
    case 'none':
      return d.sql.raw('1 = 0');
    case 'eq':
      return d.eq(table[filter.field], filter.value);
    case 'in':
      return d.inArray(table[filter.field], [...filter.values]);
    case 'and':
      return d.and(...filter.filters.map((f) => toDrizzle(f, table, d)));
    case 'or':
      return d.or(...filter.filters.map((f) => toDrizzle(f, table, d)));
  }
}
