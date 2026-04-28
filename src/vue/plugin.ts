import type { Enforcer } from '../core/enforcer.js';
import type { PolicySpec } from '../types/policy.js';
import type { Subject } from '../types/subject.js';

/**
 * Injection key under which the enforcer/subject pair is provided to the
 * Vue tree. Exported so consumers can use it with `inject(...)` directly.
 */
export const PERMISSIONS_INJECTION_KEY = Symbol.for('authkit/permissions');

export interface PermissionsBinding<P extends PolicySpec> {
  readonly enforcer: Enforcer<P>;
  readonly subject: Subject;
}

/** Minimal Vue `App` surface used by `createPermissionsPlugin`. */
export interface VueAppLike {
  provide(key: symbol, value: unknown): VueAppLike;
}

/**
 * Build a Vue 3 plugin that provides the enforcer/subject pair to
 * descendants. Use `useCan()` from this subpath to consume it.
 *
 * @example
 *   const app = createApp(App);
 *   app.use(createPermissionsPlugin({ enforcer, subject }));
 *   app.mount('#root');
 */
export function createPermissionsPlugin<P extends PolicySpec>(
  binding: PermissionsBinding<P>,
): { install(app: VueAppLike): void } {
  return {
    install(app) {
      app.provide(PERMISSIONS_INJECTION_KEY, binding);
    },
  };
}
