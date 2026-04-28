import type { AuditHook } from '../types/audit.js';

/**
 * Wrap an audit hook so it measures and reports its own execution time.
 *
 * Adds `audit_hook_duration_ms` to a metrics sink (or `console.debug`
 * by default) so a slow analytics pipeline can be detected in production.
 *
 * @param hook - hook to wrap.
 * @param sink - metrics sink; defaults to `console.debug`.
 * @returns a new hook with timing instrumentation around the original.
 *
 * @example
 *   const audit = withTiming(myHook, ({ ms }) => metrics.histogram('audit.ms', ms));
 */
export function withTiming(
  hook: AuditHook,
  sink: (sample: { ms: number; reason: string; decision: 'allow' | 'deny' }) => void = (s) => {
    // eslint-disable-next-line no-console
    console.debug('[authkit/permissions] audit timing', s);
  },
): AuditHook {
  return async (event) => {
    const start = nowMs();
    try {
      const result = hook(event);
      if (result instanceof Promise) await result;
    } finally {
      sink({ ms: nowMs() - start, reason: event.reason, decision: event.decision });
    }
  };
}

function nowMs(): number {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}
