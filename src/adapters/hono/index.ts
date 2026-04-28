import type { Enforcer } from '../../core/enforcer.js';
import type { CheckArgs } from '../../types/context.js';
import type { InferActions, InferResources, InferRoles } from '../../types/inference.js';
import type { PolicySpec } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/**
 * Minimal Hono context surface used by the adapter.
 *
 * Avoids importing `hono` at type level so the package is lint-clean even
 * when Hono is not installed; consumers using Hono get full structural
 * compatibility because they pass their own `Context`.
 */
export interface HonoContextLike {
  readonly executionCtx?: { readonly waitUntil?: (p: Promise<unknown>) => void };
  readonly var?: Readonly<Record<string, unknown>>;
}

/** Hono `MiddlewareHandler` shape. */
export type HonoMiddleware = (c: HonoContextLike, next: () => Promise<void>) => Promise<unknown> | unknown;

/** Configuration for the `honoPermissions` middleware factory. */
export interface HonoPermissionsOptions<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> {
  /** Pull a `Subject` out of the request context (set by upstream auth middleware). */
  readonly getSubject: (c: HonoContextLike) => Subject<InferRoles<P>> | Promise<Subject<InferRoles<P>>>;
  /** Build the resource/action/data triple for this route. */
  readonly require: (
    c: HonoContextLike,
  ) => Omit<CheckArgs<P, R, A>, 'subject'> | Promise<Omit<CheckArgs<P, R, A>, 'subject'>>;
  /** Optional: forwards `c.executionCtx.waitUntil` to the enforcer's audit hook. */
  readonly waitUntil?: (c: HonoContextLike) => ((p: Promise<unknown>) => void) | undefined;
}

/**
 * Build a Hono middleware that enforces a permission requirement.
 *
 * On allow, calls `next()`. On deny, the underlying `enforcer.enforce`
 * throws `PermissionError(FORBIDDEN)` and Hono's error handler turns it
 * into a 403.
 *
 * @example
 *   app.use('/api/*',
 *     honoPermissions(enforcer, {
 *       getSubject: (c) => c.var.user,
 *       require: () => ({ resource: 'document', action: 'read' }),
 *       waitUntil: (c) => c.executionCtx?.waitUntil,
 *     }),
 *   );
 */
export function honoPermissions<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(enforcer: Enforcer<P>, options: HonoPermissionsOptions<P, R, A>): HonoMiddleware {
  return async (c, next) => {
    const subject = await options.getSubject(c);
    const requirement = await options.require(c);
    const args = { subject, ...requirement } as CheckArgs<P, R, A>;
    await enforcer.enforce(args);
    await next();
  };
}
