import type { AuditEvent } from '../types/audit.js';

/**
 * Default JSON formatter for an `AuditEvent`.
 *
 * Produces a deterministic, single-line JSON string with no newlines and
 * stable key ordering — suitable for line-oriented log shippers
 * (Vector, Fluent Bit, Loki). Handles non-`JSON.stringify`-able `cause`
 * values (e.g. `Error` instances) by coercing them via `String()`.
 *
 * @param event - the audit event from the enforcer.
 * @returns single-line JSON string.
 *
 * @example
 *   logger.info(jsonFormatter(event));
 */
export function jsonFormatter(event: AuditEvent): string {
  return JSON.stringify(event, replacer);
}

function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Error) {
    return { name: value.name, message: value.message };
  }
  if (typeof value === 'bigint') return value.toString();
  return value;
}

/**
 * Build a formatter that replaces full `tenantId` strings with a short
 * stable hash for low-cardinality metric pipelines.
 *
 * **Not a security measure** — 32-bit hashes of sequential tenant ids
 * enumerate trivially. Use only where the goal is to keep tenant ids out
 * of high-cardinality metrics (e.g. Prometheus labels), not to hide them
 * from operators (plan §9.4.3).
 *
 * @returns a formatter that emits the event with `tenantId` replaced by
 *   an 8-hex-char FNV-1a 32-bit fingerprint of the original value.
 *
 * @example
 *   const audit = (event) => logger.info(tenantHashFormatter()(event));
 */
export function tenantHashFormatter(): (event: AuditEvent) => string {
  return (event) => {
    if (event.tenantId === undefined) return jsonFormatter(event);
    return jsonFormatter({
      ...event,
      tenantId: fnv1a32(event.tenantId),
    });
  };
}

function fnv1a32(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}
