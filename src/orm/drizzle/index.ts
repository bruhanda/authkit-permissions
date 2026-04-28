import type { Subject } from '../../types/subject.js';

export { toDrizzleWhere } from './filter.js';
export type { DrizzleWhere } from './filter.js';

/**
 * Configuration for `createDrizzleRoleAdapter`.
 *
 * The adapter is intentionally agnostic about your schema; it accepts a
 * pre-built query function that returns the role rows. This avoids
 * coupling to a specific Drizzle table shape or column-name convention.
 */
export interface DrizzleRoleAdapterOptions {
  /**
   * Run the membership query for `(userId, tenantId)` and return the
   * matching rows as plain objects. Each row must expose the role under
   * the `role` key. `crossTenant` is optional.
   */
  readonly query: (args: {
    readonly userId: string;
    readonly tenantId: string;
  }) => Promise<ReadonlyArray<{ readonly role: string; readonly crossTenant?: boolean }>>;
}

/**
 * Build a role-loader against a Drizzle-backed memberships table.
 *
 * @param options - the membership query closure.
 * @returns an object with `loadSubject({ userId, tenantId })`.
 *
 * @example
 *   const adapter = createDrizzleRoleAdapter({
 *     query: async ({ userId, tenantId }) =>
 *       db.select({ role: memberships.role })
 *         .from(memberships)
 *         .where(and(eq(memberships.userId, userId), eq(memberships.tenantId, tenantId))),
 *   });
 */
export function createDrizzleRoleAdapter(options: DrizzleRoleAdapterOptions): {
  loadSubject(args: { readonly userId: string; readonly tenantId: string }): Promise<Subject>;
} {
  return {
    async loadSubject({ userId, tenantId }) {
      const rows = await options.query({ userId, tenantId });
      const roles = rows.map((row) => row.role).filter((r): r is string => typeof r === 'string');
      const crossTenant = rows.some((row) => row.crossTenant === true);
      const subject: { id: string; tenantId: string; roles: string[]; crossTenant?: true } = {
        id: userId,
        tenantId,
        roles,
      };
      if (crossTenant) subject.crossTenant = true;
      return subject as Subject;
    },
  };
}
