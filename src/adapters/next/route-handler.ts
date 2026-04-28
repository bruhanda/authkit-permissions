import type { Enforcer } from '../../core/enforcer.js';
import type { CheckArgs } from '../../types/context.js';
import type { InferActions, InferResources, InferRoles } from '../../types/inference.js';
import type { PolicySpec } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/** Minimal Next.js Route Handler request surface. */
export interface NextRequestLike {
  readonly headers: Pick<Headers, 'get'>;
  readonly url: string;
  readonly nextUrl?: URL;
  readonly cookies?: { get(name: string): { value: string } | undefined };
}

/** Second argument to a Route Handler — `params`-style context. */
export interface NextRouteContext<TParams extends Record<string, string | string[]> = Record<string, string | string[]>> {
  readonly params: Promise<TParams> | TParams;
}

/**
 * Wrap a Next.js Route Handler with a permission requirement.
 *
 * The underlying handler receives the resolved subject as its third
 * argument (extending the framework's `(req, ctx)` shape), so authorised
 * code never has to re-derive it.
 *
 * @example
 *   export const GET = nextPermissions(
 *     enforcer,
 *     { getSubject: (req) => sessionFor(req), require: () => ({ resource: 'document', action: 'read' }) },
 *     async (req, { params }, { subject }) => Response.json(await load(params.id, subject)),
 *   );
 */
export function nextPermissions<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
  TParams extends Record<string, string | string[]> = Record<string, string | string[]>,
>(
  enforcer: Enforcer<P>,
  options: {
    readonly getSubject: (req: NextRequestLike) => Subject<InferRoles<P>> | Promise<Subject<InferRoles<P>>>;
    readonly require: (
      req: NextRequestLike,
      ctx: NextRouteContext<TParams>,
    ) => Omit<CheckArgs<P, R, A>, 'subject'> | Promise<Omit<CheckArgs<P, R, A>, 'subject'>>;
  },
  handler: (
    req: NextRequestLike,
    ctx: NextRouteContext<TParams>,
    extras: { readonly subject: Subject<InferRoles<P>> },
  ) => Response | Promise<Response>,
): (req: NextRequestLike, ctx: NextRouteContext<TParams>) => Promise<Response> {
  return async (req, ctx) => {
    const subject = await options.getSubject(req);
    const requirement = await options.require(req, ctx);
    await enforcer.enforce({ subject, ...requirement } as CheckArgs<P, R, A>);
    return handler(req, ctx, { subject });
  };
}
