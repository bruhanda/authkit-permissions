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
   * the `role` key.
   */
  readonly query: (args: {
    readonly userId: string;
    readonly tenantId: string;
  }) => Promise<ReadonlyArray<{ readonly role: string }>>;
}

/**
 * Build a role-loader against a Drizzle-backed memberships table.
 *
 * Per plan §9.2.4 the cross-tenant gate is "role flag + per-call opt-in"
 * — the adapter only resolves role names. A `memberships.cross_tenant`
 * column is **not** part of the contract; declare `crossTenant: true` on
 * the role in the policy and pass `allowCrossTenant: true` per call.
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
      return { id: userId, tenantId, roles } satisfies Subject;
    },
  };
}
