import { PermissionError } from '../../errors/base.js';
import { ERROR_CODES } from '../../errors/codes.js';
import type { Enforcer } from '../../core/enforcer.js';
import type { CheckArgs } from '../../types/context.js';
import type { InferActions, InferResources, InferRoles } from '../../types/inference.js';
import type { PolicySpec } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';
import type { NextRequestLike } from './route-handler.js';

/**
 * Factory for a Next.js App Router `middleware.ts` export that enforces a
 * permission requirement and passes through (returns `undefined`) when the
 * subject is allowed.
 *
 * Adapter contract is "always rethrow, framework decides" — except here:
 * Next.js Edge middleware is run before the application's error boundary,
 * so an unhandled throw produces a generic 500. To make `FORBIDDEN` map to
 * an actionable response, this adapter (and **only** this adapter) catches
 * `PermissionError(FORBIDDEN)` and returns a 403 `Response`. Every other
 * error still bubbles. The route-handler / Hono / Fastify / tRPC / Express
 * adapters do not catch — their host frameworks have an error path.
 *
 * @example
 *   // middleware.ts
 *   export const middleware = nextMiddleware(enforcer, {
 *     getSubject: (req) => sessionFor(req),
 *     require: (req) => ({ resource: 'document', action: 'read' }),
 *   });
 */
export function nextMiddleware<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(
  enforcer: Enforcer<P>,
  options: {
    readonly getSubject: (req: NextRequestLike) => Subject<InferRoles<P>> | Promise<Subject<InferRoles<P>>>;
    readonly require: (
      req: NextRequestLike,
    ) => Omit<CheckArgs<P, R, A>, 'subject'> | Promise<Omit<CheckArgs<P, R, A>, 'subject'>>;
  },
): (req: NextRequestLike) => Promise<Response | undefined> {
  return async (req) => {
    try {
      const subject = await options.getSubject(req);
      const requirement = await options.require(req);
      await enforcer.enforce({ subject, ...requirement } as CheckArgs<P, R, A>);
      return undefined;
    } catch (err) {
      if (err instanceof PermissionError && err.code === ERROR_CODES.FORBIDDEN) {
        return new Response('Forbidden', { status: 403 });
      }
      throw err;
    }
  };
}
