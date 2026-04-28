import type { Decision } from '../types/decision.js';
import type { Subject } from '../types/subject.js';
import { AuthkitPermissionsError } from './base.js';
import type { ErrorCode } from './codes.js';

/**
 * The HTTP shape produced by `PermissionError.toResponse()`.
 */
export interface PermissionErrorResponseBody {
  readonly error: string;
  readonly code: ErrorCode;
  readonly reason: string;
}

export interface PermissionErrorResponse {
  readonly status: 403;
  readonly body: PermissionErrorResponseBody;
}

/**
 * Thrown by `Permissions.enforce()` / `Ability.enforce()` when a
 * `Decision` is `allowed: false`.
 */
export class PermissionError extends AuthkitPermissionsError {
  public readonly code: 'PERMISSION_DENIED' | 'TENANT_MISMATCH' | 'CROSS_TENANT_DISALLOWED';
  public readonly decision: Decision;
  public readonly subject: Subject;
  public readonly resource: string;
  public readonly action: string;

  /**
   * @param args Decision context. The constructor picks the most specific
   *             `code` based on `decision.reason`.
   */
  public constructor(args: {
    decision: Decision;
    subject: Subject;
    resource: string;
    action: string;
    message?: string;
  }) {
    const code = pickCode(args.decision.reason);
    super(args.message ?? defaultMessage(args.resource, args.action, args.decision.reason));
    this.code = code;
    this.decision = args.decision;
    this.subject = args.subject;
    this.resource = args.resource;
    this.action = args.action;
  }

  /**
   * Convert this error into a 403 response shape suitable for
   * `Response.json(body, { status })`.
   */
  public toResponse(): PermissionErrorResponse {
    return {
      status: 403,
      body: {
        error: this.message,
        code: this.code,
        reason: this.decision.reason,
      },
    };
  }
}

function pickCode(
  reason: Decision['reason'],
): 'PERMISSION_DENIED' | 'TENANT_MISMATCH' | 'CROSS_TENANT_DISALLOWED' {
  if (reason === 'tenant_mismatch') return 'TENANT_MISMATCH';
  if (reason === 'cross_tenant_disallowed') return 'CROSS_TENANT_DISALLOWED';
  return 'PERMISSION_DENIED';
}

function defaultMessage(resource: string, action: string, reason: Decision['reason']): string {
  return `Permission denied: cannot ${action} ${resource} (${reason})`;
}
