import type { Subject } from '../../types/subject.js';

export { toMongoFilter } from './filter.js';

/**
 * Configuration for `createMongooseRoleAdapter`.
 *
 * The adapter accepts a query closure (instead of a schema/model pair)
 * so it works with both Mongoose models and the native MongoDB driver.
 */
export interface MongooseRoleAdapterOptions {
  readonly query: (args: {
    readonly userId: string;
    readonly tenantId: string;
  }) => Promise<ReadonlyArray<{ readonly role: string }>>;
}

/**
 * Build a role-loader against a Mongoose-backed memberships collection.
 *
 * Per plan §9.2.4 the cross-tenant gate is "role flag + per-call opt-in"
 * — the adapter only resolves role names. A `memberships.crossTenant`
 * field is **not** part of the contract; declare `crossTenant: true` on
 * the role in the policy and pass `allowCrossTenant: true` per call.
 *
 * @param options - the membership query closure.
 * @returns an object with `loadSubject({ userId, tenantId })`.
 *
 * @example
 *   const adapter = createMongooseRoleAdapter({
 *     query: ({ userId, tenantId }) =>
 *       Membership.find({ userId, tenantId }, { role: 1 }).lean(),
 *   });
 */
export function createMongooseRoleAdapter(options: MongooseRoleAdapterOptions): {
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
