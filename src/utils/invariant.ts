import { PolicyError, type PolicyErrorCode } from '../errors/policy-error.js';

/**
 * Throw a `PolicyError` with the given code and message if `condition`
 * is falsy. Used at policy-construction time to validate the input
 * literal before freezing.
 */
export function invariant(
  condition: unknown,
  code: PolicyErrorCode,
  message: string,
  path?: ReadonlyArray<string | number>,
): asserts condition {
  if (!condition) {
    throw new PolicyError(code, message, path ? { path } : undefined);
  }
}
