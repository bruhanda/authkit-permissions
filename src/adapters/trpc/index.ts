import type { Enforcer } from '../../core/enforcer.js';
import type { CheckArgs } from '../../types/context.js';
import type { InferActions, InferResources, InferRoles } from '../../types/inference.js';
import type { PolicySpec } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/**
 * Minimal tRPC builder surface. tRPC v11 exposes a `t.middleware(...)`
 * factory; we accept anything that quacks like it. Avoids a hard import
 * from `@trpc/server` so the lib remains zero-runtime-dep.
 */
export interface TrpcLike {
  readonly middleware: (fn: TrpcMiddlewareFn) => unknown;
}

/** Generic tRPC middleware function signature. */
export type TrpcMiddlewareFn = (opts: {
  readonly ctx: unknown;
  readonly next: (override?: { readonly ctx: unknown }) => Promise<unknown>;
}) => Promise<unknown>;

/**
 * Build a tRPC procedure-middleware factory bound to an enforcer.
 *
 * Returned helper is itself a factory — pass the resource/action triple
 * (and `getSubject` / `getRequirement` callbacks) at procedure definition
 * time, just like `requires(...)` in CASL.
 *
 * @example
 *   const requires = trpcPermissions(t, enforcer, {
 *     getSubject: (ctx) => ctx.user,
 *   });
 *
 *   export const documents = t.router({
 *     delete: t.procedure
 *       .use(requires({ resource: 'document', action: 'delete' }))
 *       .input(z.object({ id: z.string() }))
 *       .mutation(({ input, ctx }) => repo.delete(input.id)),
 *   });
 */
export function trpcPermissions<P extends PolicySpec, TCtx>(
  t: TrpcLike,
  enforcer: Enforcer<P>,
  options: {
    readonly getSubject: (ctx: TCtx) => Subject<InferRoles<P>> | Promise<Subject<InferRoles<P>>>;
  },
): <R extends InferResources<P>, A extends InferActions<P, R>>(
  requirement: Omit<CheckArgs<P, R, A>, 'subject'>,
) => unknown {
  return <R extends InferResources<P>, A extends InferActions<P, R>>(
    requirement: Omit<CheckArgs<P, R, A>, 'subject'>,
  ) =>
    t.middleware(async ({ ctx, next }) => {
      const subject = await options.getSubject(ctx as TCtx);
      await enforcer.enforce({ subject, ...requirement } as CheckArgs<P, R, A>);
      return next({ ctx });
    });
}
