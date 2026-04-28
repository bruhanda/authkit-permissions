import type { AuditEvent, AuditHook } from './hook.js';

/**
 * No-op audit hook. Useful in tests that exercise the audit path without
 * caring about the events.
 *
 * @returns An `AuditHook` that ignores every event.
 *
 * @example
 * ```ts
 * const p = permissions.withAudit(noopAudit());
 * ```
 */
export const noopAudit = (): AuditHook => (): void => {};

/**
 * Console audit hook. Writes every event to `console[level]`.
 *
 * @param opts.level Console level. Defaults to `'info'`.
 *
 * @returns An `AuditHook` that writes to the console.
 *
 * @example
 * ```ts
 * const p = permissions.withAudit(consoleAudit({ level: 'debug' }));
 * ```
 */
export const consoleAudit = (
  opts?: { level?: 'info' | 'debug' },
): AuditHook => {
  const level: 'info' | 'debug' = opts?.level ?? 'info';
  return (event: AuditEvent): void => {
    const fn = level === 'debug' ? console.debug : console.info;
    fn(
      `[authkit/permissions] ${event.decision.allowed ? 'ALLOW' : 'DENY'} ${event.action} ${event.resource}`,
      {
        subject: event.subject.id,
        tenantId: event.tenantId,
        reason: event.decision.reason,
        crossTenant: event.crossTenant,
      },
    );
  };
};
