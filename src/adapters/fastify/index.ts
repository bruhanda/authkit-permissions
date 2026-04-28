import type { Enforcer } from '../../core/enforcer.js';
import type { CheckArgs } from '../../types/context.js';
import type { InferActions, InferResources, InferRoles } from '../../types/inference.js';
import type { PolicySpec } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/** Minimal Fastify request surface. */
export interface FastifyRequestLike {
  readonly user?: unknown;
  readonly [key: string]: unknown;
}

/** Minimal Fastify reply surface (unused on allow). */
export interface FastifyReplyLike {
  code(statusCode: number): FastifyReplyLike;
  send(payload: unknown): FastifyReplyLike;
}

/** Fastify `preHandler` hook signature. */
export type FastifyPreHandler = (
  request: FastifyRequestLike,
  reply: FastifyReplyLike,
) => Promise<void> | void;

/** Configuration for the `fastifyPermissions` factory. */
export interface FastifyPermissionsOptions<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> {
  readonly enforcer: Enforcer<P>;
  readonly getSubject: (
    request: FastifyRequestLike,
  ) => Subject<InferRoles<P>> | Promise<Subject<InferRoles<P>>>;
  readonly require: (
    request: FastifyRequestLike,
  ) => Omit<CheckArgs<P, R, A>, 'subject'> | Promise<Omit<CheckArgs<P, R, A>, 'subject'>>;
}

/**
 * Build a Fastify `preHandler` that enforces a permission requirement.
 *
 * `enforcer.enforce` throws `PermissionError(FORBIDDEN)` on deny; Fastify's
 * error hook converts the error to the configured error response.
 *
 * @example
 *   app.delete('/posts/:id',
 *     { preHandler: fastifyPermissions({
 *         enforcer,
 *         getSubject: (req) => req.user as Subject,
 *         require: (req) => ({ resource: 'post', action: 'delete' }),
 *       }) },
 *     postsController.delete,
 *   );
 */
export function fastifyPermissions<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(options: FastifyPermissionsOptions<P, R, A>): FastifyPreHandler {
  const { enforcer, getSubject, require: requirementFor } = options;
  return async (request, _reply) => {
    const subject = await getSubject(request);
    const requirement = await requirementFor(request);
    await enforcer.enforce({ subject, ...requirement } as CheckArgs<P, R, A>);
  };
}
