import type { ErrorCode } from './codes.js';

/**
 * Single error class for every failure mode in `@authkit/permissions`.
 *
 * The `code` property is a discriminator from {@link ERROR_CODES} so callers
 * can branch on it without parsing the human-readable `message`. `context`
 * carries structured fields suitable for audit logs and Sentry — by
 * convention, never contains raw PII.
 *
 * @example
 *   try {
 *     await enforcer.enforce({ subject, resource: 'document', action: 'delete' });
 *   } catch (err) {
 *     if (err instanceof PermissionError && err.code === 'FORBIDDEN') {
 *       return new Response('Forbidden', { status: 403 });
 *     }
 *     throw err;
 *   }
 */
export class PermissionError extends Error {
  override readonly name = 'PermissionError' as const;

  /** Discriminator from {@link ERROR_CODES}. */
  readonly code: ErrorCode;

  /** Structured context for audit logs / Sentry. Never contains PII by default. */
  readonly context?: Readonly<Record<string, unknown>>;

  /**
   * Construct a `PermissionError`.
   *
   * @param code - one of {@link ERROR_CODES}.
   * @param message - human-readable description (English).
   * @param context - structured context, frozen on assignment.
   * @param cause - original error when wrapping (e.g. a thrown condition).
   */
  constructor(
    code: ErrorCode,
    message: string,
    context?: Record<string, unknown>,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.code = code;
    if (context !== undefined) {
      this.context = Object.freeze({ ...context });
    }
  }
}
