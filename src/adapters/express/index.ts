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

/** Minimal Express request shape. */
export interface ExpressRequestLike {
  [k: string]: unknown;
}

/** Minimal Express response shape. */
export interface ExpressResponseLike {
  status(code: number): ExpressResponseLike;
  json(body: unknown): unknown;
}

export type ExpressNext = (err?: unknown) => void;

export interface ExpressPermissionsConfig<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  readonly permissions: Permissions<TPolicy, TInstances>;
  /** Returns `null` to respond with `401`. */
  readonly getSubject: (req: ExpressRequestLike) => Subject<InferRoles<TPolicy>> | null | Promise<Subject<InferRoles<TPolicy>> | null>;
}

/**
 * Build an Express middleware that attaches a bound `Ability` to
 * `req.ability` and a sugar function `req.enforce` for use in handlers.
 *
 * @param config Adapter config — `permissions`, `getSubject`.
 *
 * @returns An Express middleware.
 *
 * @throws The middleware itself never throws; calling `req.enforce(...)`
 *         throws `PermissionError` on denial — the included error handler
 *         translates that to a 403 JSON response.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { expressPermissions, expressErrorHandler } from '@authkit/permissions/adapters/express';
 *
 * const app = express();
 * app.use(expressPermissions({ permissions, getSubject: (req) => req.user ?? null }));
 * app.delete('/posts/:id', (req, res) => {
 *   (req as any).enforce({ action: 'delete', resource: 'post' });
 *   res.json({ ok: true });
 * });
 * app.use(expressErrorHandler());
 * ```
 */
export function expressPermissions<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(
  config: ExpressPermissionsConfig<TPolicy, TInstances>,
): (
  req: ExpressRequestLike,
  res: ExpressResponseLike,
  next: ExpressNext,
) => void {
  return (req, res, next): void => {
    Promise.resolve(config.getSubject(req))
      .then((subject) => {
        if (!subject) {
          res.status(401).json({ error: 'Unauthorized', code: 'UNAUTHORIZED' });
          return;
        }
        const ability: Ability<TPolicy, TInstances> = config.permissions.abilityFor(subject);
        req['subject'] = subject;
        req['ability'] = ability;
        req['enforce'] = <
          R extends InferResources<TPolicy>,
          A extends InferActions<TPolicy, R>,
        >(args: AbilityCheckArgs<TPolicy, R, A, TInstances>): void => {
          ability.enforce(args);
        };
        next();
      })
      .catch(next);
  };
}

/**
 * Build a per-route Express handler that enforces one permission before
 * delegating to the underlying handler.
 *
 * @param requirement The `{ resource, action }` to enforce.
 *
 * @returns An Express middleware that 403s on denial.
 *
 * @throws Never throws — denials are translated to a JSON response.
 *
 * @example
 * ```ts
 * app.delete('/posts/:id',
 *   requirePermission({ resource: 'post', action: 'delete' }),
 *   handler,
 * );
 * ```
 */
export function requirePermission<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  A extends InferActions<TPolicy, R>,
>(
  requirement: { resource: R; action: A },
): (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNext) => void {
  return (req, res, next): void => {
    const ability = req['ability'] as Ability<TPolicy> | undefined;
    if (!ability) {
      res.status(401).json({ error: 'Unauthorized', code: 'UNAUTHORIZED' });
      return;
    }
    try {
      ability.enforce(requirement as never);
      next();
    } catch (err) {
      if (err instanceof PermissionError) {
        const r = err.toResponse();
        res.status(r.status).json(r.body);
        return;
      }
      next(err);
    }
  };
}

/**
 * Standard error handler that converts `PermissionError` into a 403 JSON
 * response. Mount AFTER your routes.
 *
 * @returns An Express error-handling middleware.
 */
export function expressErrorHandler(): (
  err: unknown,
  _req: ExpressRequestLike,
  res: ExpressResponseLike,
  next: ExpressNext,
) => void {
  return (err, _req, res, next): void => {
    if (err instanceof PermissionError) {
      const r = err.toResponse();
      res.status(r.status).json(r.body);
      return;
    }
    next(err);
  };
}
