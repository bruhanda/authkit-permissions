import type { Subject } from '../types/subject.js';

/**
 * Construct a properly-typed `Subject`.
 *
 * Pure helper — no state, no side effects. Useful at the boundary between
 * an authentication library (`@authkit/session`, NextAuth, custom JWT) and
 * the enforcer.
 *
 * @param init - subject fields. Roles are typed as a literal-preserving
 *   readonly tuple so downstream `enforcer.check` calls infer the role
 *   union.
 * @returns a frozen `Subject` instance.
 *
 * @example
 *   const subject = createSubject({
 *     id: user.id,
 *     roles: ['admin', 'member'] as const,
 *     tenantId: org.id,
 *   });
 */
export function createSubject<TRole extends string>(init: {
  readonly id: string;
  readonly roles: ReadonlyArray<TRole>;
  readonly tenantId?: string;
  readonly attrs?: Readonly<Record<string, unknown>>;
}): Subject<TRole> {
  const subject: {
    id: string;
    roles: ReadonlyArray<TRole>;
    tenantId?: string;
    attrs?: Readonly<Record<string, unknown>>;
  } = {
    id: init.id,
    roles: init.roles,
  };
  if (init.tenantId !== undefined) subject.tenantId = init.tenantId;
  if (init.attrs !== undefined) subject.attrs = init.attrs;
  return Object.freeze(subject);
}
