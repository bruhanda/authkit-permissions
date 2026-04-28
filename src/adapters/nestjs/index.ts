import type { Enforcer } from '../../core/enforcer.js';
import type { CheckArgs } from '../../types/context.js';
import type { InferActions, InferResources, InferRoles } from '../../types/inference.js';
import type { PolicySpec } from '../../types/policy.js';
import type { Subject } from '../../types/subject.js';

/**
 * Metadata key used by `@Requires()` to attach the permission requirement
 * to a controller method, and by `PermissionsGuard` to read it back.
 */
export const REQUIRES_METADATA_KEY = 'authkit/requires';

/**
 * Minimal `ExecutionContext` interface used by the guard. Avoids importing
 * `@nestjs/common` at type-level; consumers using NestJS pass their own
 * `ExecutionContext` and structural typing keeps it compatible.
 */
export interface NestExecutionContextLike {
  switchToHttp(): { getRequest(): { user?: unknown } & Record<string, unknown> };
  getHandler(): object;
}

/** `Reflector`-like surface from `@nestjs/core`. */
export interface ReflectorLike {
  get<T>(key: string, target: object): T | undefined;
}

/**
 * Per-route permission requirement attached by `@Requires()`.
 */
export interface PermissionRequirement<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> {
  readonly resource: R;
  readonly action: A;
}

/**
 * Method decorator factory. Attaches a `PermissionRequirement` to the
 * decorated handler so `PermissionsGuard` can read it via `Reflector`.
 *
 * Implemented with `Reflect.defineMetadata` — no NestJS import — so the
 * decorator stays portable. NestJS users already have `reflect-metadata`
 * loaded (it's a NestJS bootstrap requirement).
 *
 * @example
 *   @Get(':id')
 *   @Requires({ resource: 'document', action: 'read' })
 *   read(@Param('id') id: string) { ... }
 */
export function Requires<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(req: PermissionRequirement<P, R, A>): MethodDecorator {
  return (target, propertyKey, descriptor) => {
    const handler = descriptor.value;
    if (typeof handler === 'function') {
      defineMetadata(REQUIRES_METADATA_KEY, req, handler);
    } else {
      defineMetadata(REQUIRES_METADATA_KEY, req, target as object, propertyKey as string | symbol);
    }
  };
}

/**
 * NestJS-compatible guard. Provide a subclass that wires up your enforcer
 * and a subject-resolver, then list it in `app.useGlobalGuards(...)` or
 * a controller's `@UseGuards(...)`.
 *
 * The library exposes the abstract base so consumers can decide how to
 * load their `Subject` from the request without bringing a hard dep on
 * `@nestjs/common` into the package.
 *
 * @example
 *   @Injectable()
 *   class AppPermissionsGuard extends PermissionsGuard {
 *     constructor(reflector: Reflector) {
 *       super(reflector, enforcer, (req) => req.user as Subject);
 *     }
 *   }
 */
export class PermissionsGuard<P extends PolicySpec> {
  constructor(
    private readonly reflector: ReflectorLike,
    private readonly enforcer: Enforcer<P>,
    private readonly getSubject: (req: Record<string, unknown>) => Subject<InferRoles<P>> | Promise<Subject<InferRoles<P>>>,
  ) {}

  /**
   * NestJS guard contract. Returns `true` when the action is allowed,
   * throws `PermissionError(FORBIDDEN)` on deny.
   */
  async canActivate(context: NestExecutionContextLike): Promise<boolean> {
    const requirement = this.reflector.get<PermissionRequirement<P, never, never>>(
      REQUIRES_METADATA_KEY,
      context.getHandler(),
    );
    if (requirement === undefined) return true;
    const request = context.switchToHttp().getRequest();
    const subject = await this.getSubject(request);
    await this.enforcer.enforce({ subject, ...requirement } as CheckArgs<P, never, never>);
    return true;
  }
}

type ReflectMetadata = {
  defineMetadata(key: string, value: unknown, target: object, property?: string | symbol): void;
};

function defineMetadata(
  key: string,
  value: unknown,
  target: object,
  property?: string | symbol,
): void {
  const reflect = (globalThis as unknown as { Reflect?: ReflectMetadata }).Reflect;
  if (reflect !== undefined && typeof reflect.defineMetadata === 'function') {
    if (property !== undefined) reflect.defineMetadata(key, value, target, property);
    else reflect.defineMetadata(key, value, target);
    return;
  }
  // Fallback: stash on the target directly. Only reached in environments
  // without `reflect-metadata` — where NestJS itself wouldn't boot.
  (target as Record<string, unknown>)[`__authkit_meta_${key}`] = value;
}
