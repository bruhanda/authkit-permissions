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
 * On deny, returns a 403 `Response` so the request is short-circuited
 * before hitting any route handler.
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
