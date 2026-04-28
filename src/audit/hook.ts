import type { AuditHook } from '../types/audit.js';

/**
 * Compose multiple audit hooks into one. Hooks run **left-to-right** and
 * any rejection from any hook propagates after the previous ones have
 * resolved (errors are aggregated into a single rejection).
 *
 * @param hooks - audit hooks to compose.
 * @returns a single hook that fans the event out to each child.
 *
 * @example
 *   const audit = composeAudit(
 *     (event) => logger.info(event),
 *     (event) => Sentry.addBreadcrumb({ category: 'authz', data: event }),
 *   );
 */
export function composeAudit(...hooks: ReadonlyArray<AuditHook>): AuditHook {
  if (hooks.length === 0) return () => undefined;
  if (hooks.length === 1) return hooks[0] as AuditHook;
  return async (event) => {
    const errors: unknown[] = [];
    for (const hook of hooks) {
      try {
        const result = hook(event);
        if (result instanceof Promise) await result;
      } catch (err) {
        errors.push(err);
      }
    }
    if (errors.length === 1) throw errors[0];
    if (errors.length > 1) throw new AggregateError(errors, 'audit hooks failed');
  };
}
