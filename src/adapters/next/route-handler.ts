import type { Ability } from '../../core/ability.js';
import { PermissionError } from '../../errors/permission-error.js';
import type { Permissions } from '../../core/permissions.js';
import type { AbilityCheckArgs } from '../../types/check-args.js';
import type {
  DefaultInstances,
  InferActions,
  InferResources,
  InferRoles,
  ResourceInstanceMap,
} from '../../types/inference.js';
import type { PolicyDefinition } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/** Minimal subset of `next/server` we need. */
export interface NextRouteContext<TParams = Record<string, string>> {
  readonly params: TParams;
}

export interface ProtectRouteHandlerArgs<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
  TParams = Record<string, string>,
> extends NextRouteContext<TParams> {
  readonly subject: Subject<InferRoles<TPolicy>>;
  readonly ability: Ability<TPolicy, TInstances>;
}

export interface ProtectRouteOptions<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
> {
  readonly action: A;
  readonly resource: R;
  /**
   * Resolve the subject for this request. Return `null` to short-circuit
   * with a 401 response.
   */
  readonly getSubject?: (
    req: Request,
  ) => Subject<InferRoles<TPolicy>> | null | Promise<Subject<InferRoles<TPolicy>> | null>;
}

/**
 * Wrap a Next.js App Router route handler with a permission check.
 *
 * @param permissions A `Permissions` instance.
 * @param requirement The permission to enforce: `{ resource, action }` plus
 *                    an optional `getSubject`.
 * @param handler The original route handler. Receives the standard
 *                `(req, ctx)` plus a resolved `subject` and `ability`.
 *
 * @returns A new handler that 401s when no subject is present, 403s when
 *          the permission is denied, and otherwise delegates to `handler`.
 *
 * @throws Never throws — denials are converted to JSON responses.
 *
 * @example
 * ```ts
 * import { protectRoute } from '@authkit/permissions/adapters/next';
 *
 * export const DELETE = protectRoute(
 *   permissions,
 *   { resource: 'post', action: 'delete', getSubject: getSessionUser },
 *   async (req, { params, subject }) => {
 *     await deletePost(params.id);
 *     return Response.json({ ok: true });
 *   },
 * );
 * ```
 */
export function protectRoute<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy>,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
  TParams = Record<string, string>,
>(
  permissions: Permissions<TPolicy, TInstances>,
  requirement: ProtectRouteOptions<TPolicy, R, A>,
  handler: (
    req: Request,
    ctx: ProtectRouteHandlerArgs<TPolicy, TInstances, TParams>,
  ) => Promise<Response> | Response,
): (req: Request, ctx: NextRouteContext<TParams>) => Promise<Response> {
  return async (req, ctx): Promise<Response> => {
    const subject = requirement.getSubject ? await requirement.getSubject(req) : null;
    if (!subject) {
      return Response.json({ error: 'Unauthorized', code: 'UNAUTHORIZED' }, { status: 401 });
    }

    const ability = permissions.abilityFor(subject);
    try {
      ability.enforce({
        resource: requirement.resource,
        action: requirement.action,
      } as AbilityCheckArgs<TPolicy, R, A, TInstances>);
    } catch (err) {
      if (err instanceof PermissionError) {
        const r = err.toResponse();
        return Response.json(r.body, { status: r.status });
      }
      throw err;
    }

    return handler(req, { ...ctx, subject, ability });
  };
}
