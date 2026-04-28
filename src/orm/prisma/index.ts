import type { Subject } from '../../types/subject.js';

export { toPrismaWhere } from './filter.js';

/**
 * Configuration for `createPrismaRoleAdapter`.
 *
 * All field names are configurable so the adapter slots into existing
 * schemas without forcing a column rename.
 */
export interface PrismaRoleAdapterOptions {
  /** Lowercased model name as it appears on the Prisma client. */
  readonly membershipModel: string;
  /** FK column to the user. */
  readonly userField: string;
  /** Tenant id column (typically `tenantId` / `organizationId`). */
  readonly tenantField: string;
  /** Role column (string or enum mapped to string at the boundary). */
  readonly roleField: string;
}

/**
 * Minimal Prisma client shape used by the adapter — `findMany` on a
 * configurable model. Avoids importing `@prisma/client` (peer dep) at
 * type level.
 */
export interface PrismaClientLike {
  readonly [model: string]: {
    findMany(args: {
      readonly where: Record<string, unknown>;
      readonly select?: Record<string, true>;
    }): Promise<ReadonlyArray<Record<string, unknown>>>;
  };
}

/**
 * Build a role-loader for Prisma-backed memberships.
 *
 * Per plan §9.2.4 the cross-tenant gate is "role flag + per-call opt-in":
 * the adapter only loads the role names. A `memberships.cross_tenant` column
 * is **not** part of the contract — declare `crossTenant: true` on the role
 * in the policy and pass `allowCrossTenant: true` per call instead.
 *
 * @param prisma - Prisma client instance.
 * @param options - column-name mapping.
 * @returns an object with `loadSubject({ userId, tenantId })`.
 *
 * @example
 *   const adapter = createPrismaRoleAdapter(prisma, {
 *     membershipModel: 'membership',
 *     userField: 'userId',
 *     tenantField: 'tenantId',
 *     roleField: 'role',
 *   });
 *   const subject = await adapter.loadSubject({ userId, tenantId });
 */
export function createPrismaRoleAdapter(
  prisma: PrismaClientLike,
  options: PrismaRoleAdapterOptions,
): {
  loadSubject(args: { readonly userId: string; readonly tenantId: string }): Promise<Subject>;
} {
  const { membershipModel, userField, tenantField, roleField } = options;
  return {
    async loadSubject({ userId, tenantId }) {
      const rows = await prisma[membershipModel]?.findMany({
        where: { [userField]: userId, [tenantField]: tenantId },
        select: { [roleField]: true },
      });
      if (rows === undefined) {
        throw new Error(`Prisma model "${membershipModel}" not found on client`);
      }
      const roles = rows
        .map((row) => row[roleField])
        .filter((v): v is string => typeof v === 'string');
      return { id: userId, tenantId, roles } satisfies Subject;
    },
  };
}
