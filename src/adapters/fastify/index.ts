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

/** Minimal Fastify-like app surface. */
export interface FastifyLikeApp {
  decorateRequest(name: string, defaultValue: unknown): void;
  addHook(name: 'preHandler', fn: FastifyHook): void;
  setErrorHandler(fn: (err: unknown, req: FastifyLikeRequest, reply: FastifyLikeReply) => unknown): void;
}

export interface FastifyLikeRequest {
  [k: string]: unknown;
}

export interface FastifyLikeReply {
  status(code: number): FastifyLikeReply;
  send(body: unknown): unknown;
}

export type FastifyHook = (req: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void> | void;

export interface FastifyPermissionsConfig<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  readonly permissions: Permissions<TPolicy, TInstances>;
  readonly getSubject: (
    req: FastifyLikeRequest,
  ) => Subject<InferRoles<TPolicy>> | null | Promise<Subject<InferRoles<TPolicy>> | null>;
}

/**
 * Register the permissions plugin on a Fastify-like app. Decorates every
 * request with `subject` / `ability` / `enforce` and installs an error
 * handler that converts `PermissionError` into a 403 JSON response.
 *
 * @param app A Fastify (or compatible) instance.
 * @param config Adapter config — `permissions`, `getSubject`.
 *
 * @returns `void`.
 *
 * @throws Never throws.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import { fastifyPermissions } from '@authkit/permissions/adapters/fastify';
 *
 * const app = Fastify();
 * fastifyPermissions(app, { permissions, getSubject: (req) => req.user ?? null });
 * app.delete('/posts/:id', async (req) => {
 *   (req as any).enforce({ action: 'delete', resource: 'post' });
 *   return { ok: true };
 * });
 * ```
 */
export function fastifyPermissions<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(app: FastifyLikeApp, config: FastifyPermissionsConfig<TPolicy, TInstances>): void {
  app.decorateRequest('subject', null);
  app.decorateRequest('ability', null);
  app.decorateRequest('enforce', null);

  app.addHook('preHandler', async (req, reply) => {
    const subject = await config.getSubject(req);
    if (!subject) {
      reply.status(401).send({ error: 'Unauthorized', code: 'UNAUTHORIZED' });
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
  });

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof PermissionError) {
      const r = err.toResponse();
      reply.status(r.status).send(r.body);
      return;
    }
    throw err;
  });
}
