import type { Permissions } from '../../core/permissions.js';
import type { CheckArgs } from '../../types/check-args.js';
import type {
  DefaultInstances,
  InferActions,
  InferResources,
  InferRoles,
  ResourceInstanceMap,
} from '../../types/inference.js';
import type { PolicyDefinition } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';
import { PermissionError } from '../../errors/permission-error.js';

/**
 * Minimal subset of the Hono context surface we depend on. Avoids importing
 * `hono` directly so consumers without Hono do not pay the resolution cost.
 */
export interface HonoLikeContext {
  set(key: string, value: unknown): void;
  get<T = unknown>(key: string): T;
  json(body: unknown, status?: number): unknown;
  req: { method: string; url: string };
}

export type HonoNext = () => Promise<void>;

/**
 * Configuration for `honoPermissions()`.
 */
export interface HonoPermissionsConfig<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  readonly permissions: Permissions<TPolicy, TInstances>;
  /**
   * Resolve the request subject. Return `null` to short-circuit the
   * middleware with `401`.
   */
  readonly getSubject: (c: HonoLikeContext) => Subject<InferRoles<TPolicy>> | null | Promise<Subject<InferRoles<TPolicy>> | null>;
  /** Optional override for the variable key used to expose the bound ability. */
  readonly contextKey?: string;
}

/**
 * Build a Hono middleware that exposes a per-request `enforce()` helper
 * via `c.var.enforce(...)` (or the configured `contextKey`).
 *
 * @param config Adapter config — `permissions`, `getSubject`, optional `contextKey`.
 *
 * @returns A Hono middleware function.
 *
 * @throws The middleware itself never throws; downstream handlers may
 *         invoke `enforce()` which throws `PermissionError` on denial.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { honoPermissions } from '@authkit/permissions/adapters/hono';
 *
 * const app = new Hono();
 * app.use('*', honoPermissions({ permissions, getSubject: (c) => c.get('user') }));
 * app.delete('/posts/:id', (c) => {
 *   c.var.enforce({ action: 'delete', resource: 'post' });
 *   return c.json({ ok: true });
 * });
 * ```
 */
export function honoPermissions<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(
  config: HonoPermissionsConfig<TPolicy, TInstances>,
): (c: HonoLikeContext, next: HonoNext) => Promise<unknown> {
  const key = config.contextKey ?? 'enforce';

  return async (c, next): Promise<unknown> => {
    const subject = await config.getSubject(c);
    if (!subject) {
      return c.json({ error: 'Unauthorized', code: 'UNAUTHORIZED' }, 401);
    }

    const ability = config.permissions.abilityFor(subject);
    c.set('subject', subject);
    c.set('ability', ability);
    c.set(key, <
      R extends InferResources<TPolicy>,
      A extends InferActions<TPolicy, R>,
    >(args: Omit<CheckArgs<TPolicy, R, A, TInstances>, 'subject'>): void => {
      ability.enforce(args);
    });

    try {
      return await next();
    } catch (err) {
      if (err instanceof PermissionError) {
        const r = err.toResponse();
        return c.json(r.body, r.status);
      }
      throw err;
    }
  };
}
