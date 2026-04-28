import type { AccessibleByFilter } from '../../core/accessible-by.js';

/**
 * Prisma `where` clause shape produced by `toPrisma`. Kept as
 * `Record<string, unknown>` so consumers do not need a Prisma type
 * import in their own code paths.
 */
export type PrismaWhere = Record<string, unknown>;

/**
 * Translate an `AccessibleByFilter` AST to a Prisma `where` clause.
 *
 * `kind: 'all'` becomes `{}` (no constraint), `kind: 'none'` becomes a
 * predicate that is provably false (`AND: [{ id: null }, { id: { not: null } }]`)
 * so the query returns zero rows without a round trip.
 *
 * @param filter The AST returned by `accessibleBy()`.
 *
 * @returns A Prisma-compatible `where` object.
 *
 * @throws Never throws.
 *
 * @example
 * ```ts
 * const filter = accessibleBy(ability, { resource: 'post', action: 'read' });
 * const posts = await prisma.post.findMany({ where: toPrisma(filter) });
 * ```
 */
export function toPrisma(filter: AccessibleByFilter): PrismaWhere {
  switch (filter.kind) {
    case 'all':
      return {};
    case 'none':
      return { AND: [{ id: null }, { id: { not: null } }] };
    case 'eq':
      return { [filter.field]: filter.value };
    case 'in':
      return { [filter.field]: { in: [...filter.values] } };
    case 'and':
      return { AND: filter.filters.map((f) => toPrisma(f)) };
    case 'or':
      return { OR: filter.filters.map((f) => toPrisma(f)) };
  }
}
