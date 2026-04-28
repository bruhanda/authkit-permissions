import type { Permissions } from '../../core/permissions.js';
import type {
  DefaultInstances,
  InferRoles,
  ResourceInstanceMap,
} from '../../types/inference.js';
import type { PolicyDefinition } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/**
 * Subset of the Next.js middleware response surface. We avoid importing
 * `next/server` directly so consumers without Next still type-check.
 */
export interface NextMiddlewareResponse {
  readonly status: number;
  readonly redirect?: string;
}

export interface NextPermissionsConfig<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  readonly permissions: Permissions<TPolicy, TInstances>;
  /**
   * Resolve the request subject. Return `null` to short-circuit with the
   * configured `unauthorizedRedirect` (or a 401 JSON response).
   */
  readonly getSubject: (
    req: Request,
  ) => Subject<InferRoles<TPolicy>> | null | Promise<Subject<InferRoles<TPolicy>> | null>;
  /**
   * Optional redirect URL when no subject is available. Defaults to a
   * 401 JSON response.
   */
  readonly unauthorizedRedirect?: string;
}

/**
 * Build a Next.js App Router middleware that resolves the subject on every
 * request and, when missing, either redirects to a configured login page
 * or replies with a 401 JSON response.
 *
 * @param config Adapter config — `permissions`, `getSubject`, optional
 *               `unauthorizedRedirect`.
 *
 * @returns A middleware function compatible with `export default` from
 *          `middleware.ts`.
 *
 * @throws Never throws.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { nextPermissions } from '@authkit/permissions/adapters/next';
 * import { permissions } from '@/lib/permissions';
 * import { getSessionUser } from '@/lib/session';
 *
 * export default nextPermissions({
 *   permissions,
 *   getSubject: getSessionUser,
 *   unauthorizedRedirect: '/login',
 * });
 * ```
 */
export function nextPermissions<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(
  config: NextPermissionsConfig<TPolicy, TInstances>,
): (req: Request) => Promise<Response> {
  return async (req: Request): Promise<Response> => {
    const subject = await config.getSubject(req);
    if (subject) {
      // Pass-through: in App Router `middleware.ts` returning `undefined`
      // continues the chain. When the consumer chooses this `Response`
      // shape (e.g. `NextResponse.next()`) we mimic it by signalling 200.
      return new Response(null, { status: 200 });
    }
    if (config.unauthorizedRedirect) {
      const url = new URL(config.unauthorizedRedirect, req.url);
      return Response.redirect(url, 307);
    }
    return Response.json(
      { error: 'Unauthorized', code: 'UNAUTHORIZED' },
      { status: 401 },
    );
  };
}
