import type { Enforcer } from '../../core/enforcer.js';
import type { PolicySpec } from '../../types/policy.js';

/**
 * Tokens used by `PermissionsModule.forRoot` to inject the enforcer into
 * Nest's DI container.
 */
export const PERMISSIONS_ENFORCER = 'authkit:permissions:enforcer';

/**
 * Shape returned by `PermissionsModule.forRoot`. Mirrors NestJS's
 * `DynamicModule` so the result spreads into `@Module({ imports: [...] })`
 * without an extra cast.
 */
export interface PermissionsDynamicModule<P extends PolicySpec> {
  readonly module: typeof PermissionsModule;
  readonly providers: ReadonlyArray<{ provide: string; useValue: Enforcer<P> }>;
  readonly exports: ReadonlyArray<string>;
  readonly global: true;
}

/**
 * NestJS dynamic module factory.
 *
 * Avoids importing `@nestjs/common` at type-level — returns a plain object
 * matching Nest's `DynamicModule` shape. Consumers that have NestJS
 * installed can spread the result into `imports` directly.
 *
 * @example
 *   @Module({ imports: [PermissionsModule.forRoot(enforcer)] })
 *   export class AppModule {}
 */
export const PermissionsModule: {
  forRoot<P extends PolicySpec>(enforcer: Enforcer<P>): PermissionsDynamicModule<P>;
} = {
  forRoot<P extends PolicySpec>(enforcer: Enforcer<P>): PermissionsDynamicModule<P> {
    return {
      module: PermissionsModule,
      providers: [{ provide: PERMISSIONS_ENFORCER, useValue: enforcer }],
      exports: [PERMISSIONS_ENFORCER],
      global: true,
    };
  },
};
