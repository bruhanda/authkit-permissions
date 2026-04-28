import type { ErrorCode } from './codes.js';

/**
 * Base class for every error thrown by `@authkit/permissions`.
 *
 * Subclasses pin a literal `code` value, which adapters use to map
 * exceptions to HTTP responses without `instanceof` chains.
 */
export abstract class AuthkitPermissionsError extends Error {
  public abstract readonly code: ErrorCode;

  protected constructor(message: string, options?: { cause?: unknown }) {
    super(message, options as ErrorOptions);
    this.name = new.target.name;
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, new.target);
    }
  }
}
