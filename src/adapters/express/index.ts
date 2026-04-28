import type { Enforcer } from '../../core/enforcer.js';
import type { CheckArgs } from '../../types/context.js';
import type { InferActions, InferResources, InferRoles } from '../../types/inference.js';
import type { PolicySpec } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/** Minimal Express request shape. */
export interface ExpressRequestLike {
  readonly user?: unknown;
  readonly [key: string]: unknown;
}

/** Minimal Express response shape (currently unused — kept for future extension). */
export interface ExpressResponseLike {
  status(code: number): ExpressResponseLike;
  json(body: unknown): ExpressResponseLike;
}

/** Express `RequestHandler` shape (without the full body). */
export type ExpressMiddleware = (
  req: ExpressRequestLike,
  res: ExpressResponseLike,
  next: (err?: unknown) => void,
) => void | Promise<void>;

/** Configuration for the `expressPermissions` middleware factory. */
export interface ExpressPermissionsOptions<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> {
  /** Pull a `Subject` out of the request (set by upstream auth middleware). */
  readonly getSubject: (
    req: ExpressRequestLike,
  ) => Subject<InferRoles<P>> | Promise<Subject<InferRoles<P>>>;
  /** Build the resource/action/data triple for this route. */
  readonly require: (
    req: ExpressRequestLike,
  ) => Omit<CheckArgs<P, R, A>, 'subject'> | Promise<Omit<CheckArgs<P, R, A>, 'subject'>>;
}

/**
 * Build an Express middleware that enforces a permission requirement.
 *
 * Always forwards `PermissionError(FORBIDDEN)` (and any other error) to
 * `next(err)` — the application's error handler decides the response. This
 * matches the contract used by Hono, Fastify, tRPC, and Next route handlers
 * ("always rethrow, framework decides"). Mount your own
 * `app.use((err, req, res, next) => …)` to map `FORBIDDEN` to JSON / HTML.
 *
 * @example
 *   app.delete('/posts/:id',
 *     expressPermissions(enforcer, {
 *       getSubject: (req) => req.user as Subject,
 *       require: (req) => ({ resource: 'post', action: 'delete', data: { id: req.params.id } }),
 *     }),
 *     postsController.delete,
 *   );
 */
export function expressPermissions<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(enforcer: Enforcer<P>, options: ExpressPermissionsOptions<P, R, A>): ExpressMiddleware {
  return async (req, _res, next) => {
    try {
      const subject = await options.getSubject(req);
      const requirement = await options.require(req);
      await enforcer.enforce({ subject, ...requirement } as CheckArgs<P, R, A>);
      next();
    } catch (err) {
      next(err);
    }
  };
}
