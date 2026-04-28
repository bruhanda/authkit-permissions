import type { AuditEvent, AuditHook } from '../audit/hook.js';
import { AuditError } from '../errors/audit-error.js';
import { PermissionError } from '../errors/permission-error.js';
import { TenantMismatchError } from '../errors/tenant-mismatch-error.js';
import type { CheckArgs } from '../types/check-args.js';
import type { Decision } from '../types/decision.js';
import type {
  DefaultInstances,
  InferActions,
  InferResources,
  InferRoles,
  ResourceInstanceMap,
} from '../types/inference.js';
import type { PolicyDefinition } from '../types/policy.js';
import type { ResourceInstance } from '../types/instances.js';
import type { Subject } from '../types/subject.js';
import { isDev, warnOnce } from '../utils/env.js';
import type { Ability } from './ability.js';
import { createAbility } from './ability.js';
import { denyNoMatch, denyNoRoles, makeDecision } from './decision.js';
import {
  evaluateAsync,
  evaluateSync,
  type CompiledPolicy,
} from './evaluator.js';
import { evaluateTenantGuard } from './tenant.js';

const defaultNow = (): Date => new Date();

/**
 * The runtime object returned by `definePolicy()`. Every check goes through
 * an instance of this interface, including the per-subject `Ability`.
 */
export interface Permissions<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
> {
  /**
   * Synchronous permission check. Returns a fully-described `Decision`.
   *
   * @throws Never throws; denied permissions yield `{ allowed: false, ... }`.
   */
  check<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: CheckArgs<TPolicy, R, A, TInstances>,
  ): Decision;

  /**
   * Async variant. Use when at least one applicable rule has an async
   * condition (e.g. DB lookup of membership).
   *
   * @throws Never throws on a denied decision; condition rejections are
   *         captured into `{ reason: 'condition_threw' }`.
   */
  checkAsync<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(
    args: CheckArgs<TPolicy, R, A, TInstances>,
  ): Promise<Decision>;

  /**
   * Sugar over `check(...).allowed`.
   *
   * @returns `true` when the action is allowed.
   */
  can<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: CheckArgs<TPolicy, R, A, TInstances>,
  ): boolean;

  /**
   * Sugar over `!check(...).allowed`.
   *
   * @returns `true` when the action is denied.
   */
  cannot<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: CheckArgs<TPolicy, R, A, TInstances>,
  ): boolean;

  /**
   * Throws `PermissionError` (or `TenantMismatchError`) if denied.
   *
   * @throws {PermissionError} When the decision is `allowed: false`.
   */
  enforce<R extends InferResources<TPolicy>, A extends InferActions<TPolicy, R>>(
    args: CheckArgs<TPolicy, R, A, TInstances>,
  ): void;

  /**
   * Async variant of `enforce()` for policies with async conditions.
   *
   * @throws {PermissionError} When the decision is `allowed: false`.
   */
  enforceAsync<
    R extends InferResources<TPolicy>,
    A extends InferActions<TPolicy, R>,
  >(
    args: CheckArgs<TPolicy, R, A, TInstances>,
  ): Promise<void>;

  /**
   * Returns an `Ability` bound to a given subject. Useful inside request
   * handlers to avoid passing `subject` to every check, and to enable
   * per-request memoization (the same `subject` evaluated twice for the
   * same `(resource, action)` reuses the cached decision — conditions
   * excluded).
   */
  abilityFor(subject: Subject<InferRoles<TPolicy>>): Ability<TPolicy, TInstances>;

  /**
   * Returns a NEW `Permissions` with the audit hook attached. The original
   * instance is unchanged. Calling `withAudit()` twice replaces the hook
   * (latest wins).
   */
  withAudit(hook: AuditHook): Permissions<TPolicy, TInstances>;

  /** Read-only access to the frozen, normalized policy (debugging/tests). */
  readonly policy: Readonly<TPolicy>;

  /** @internal — used by `serialize()` and `accessibleBy()`. */
  readonly compiled: CompiledPolicy;
}

/**
 * Build the runtime `Permissions` object from a frozen policy literal and
 * its compiled representation. Internal — `definePolicy()` is the public
 * factory.
 */
export function createPermissions<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(
  policy: TPolicy,
  compiled: CompiledPolicy,
  audit?: AuditHook,
): Permissions<TPolicy, TInstances> {
  const now = defaultNow;

  const checkInternal = (args: CheckArgs<TPolicy, never, never, TInstances>): Decision => {
    const guarded = applyTenantGuard(args.subject, args.target, compiled);
    if (guarded) {
      const dec = guarded;
      runAuditFireAndForget(audit, args, dec, compiled);
      return dec;
    }

    if (args.subject.roles.length === 0) {
      const dec = denyNoRoles();
      runAuditFireAndForget(audit, args, dec, compiled);
      return dec;
    }

    const effectiveRoles = expandRoles(args.subject.roles, compiled);
    if (effectiveRoles.length === 0) {
      const dec = denyNoMatch();
      runAuditFireAndForget(audit, args, dec, compiled);
      return dec;
    }

    const decision = evaluateSync({
      compiled,
      effectiveRoles,
      resource: args.resource as string,
      action: args.action as string,
      subject: args.subject,
      target: args.target as ResourceInstance | undefined,
      context: args.context ?? {},
      now,
    });

    if (decision.warning === 'async_condition_in_sync_check' && isDev()) {
      warnOnce(
        'async-in-sync',
        '[@authkit/permissions] check() encountered an async condition. Use checkAsync() instead.',
      );
    }

    runAuditFireAndForget(audit, args, decision, compiled);
    return decision;
  };

  const checkAsyncInternal = async (
    args: CheckArgs<TPolicy, never, never, TInstances>,
  ): Promise<Decision> => {
    const guarded = applyTenantGuard(args.subject, args.target, compiled);
    if (guarded) {
      const dec = guarded;
      await runAuditAwait(audit, args, dec, compiled);
      return dec;
    }

    if (args.subject.roles.length === 0) {
      const dec = denyNoRoles();
      await runAuditAwait(audit, args, dec, compiled);
      return dec;
    }

    const effectiveRoles = expandRoles(args.subject.roles, compiled);
    if (effectiveRoles.length === 0) {
      const dec = denyNoMatch();
      await runAuditAwait(audit, args, dec, compiled);
      return dec;
    }

    const decision = await evaluateAsync({
      compiled,
      effectiveRoles,
      resource: args.resource as string,
      action: args.action as string,
      subject: args.subject,
      target: args.target as ResourceInstance | undefined,
      context: args.context ?? {},
      now,
    });

    return await runAuditAwaitWithFailureMode(audit, args, decision, compiled);
  };

  const enforceInternal = (args: CheckArgs<TPolicy, never, never, TInstances>): void => {
    const decision = checkInternal(args);
    if (!decision.allowed) {
      throw buildError(decision, args);
    }
  };

  const enforceAsyncInternal = async (
    args: CheckArgs<TPolicy, never, never, TInstances>,
  ): Promise<void> => {
    const decision = await checkAsyncInternal(args);
    if (!decision.allowed) {
      throw buildError(decision, args);
    }
  };

  const permissions: Permissions<TPolicy, TInstances> = {
    policy,
    compiled,
    check: checkInternal as Permissions<TPolicy, TInstances>['check'],
    checkAsync: checkAsyncInternal as Permissions<TPolicy, TInstances>['checkAsync'],
    can: (args) => checkInternal(args as never).allowed,
    cannot: (args) => !checkInternal(args as never).allowed,
    enforce: enforceInternal as Permissions<TPolicy, TInstances>['enforce'],
    enforceAsync: enforceAsyncInternal as Permissions<TPolicy, TInstances>['enforceAsync'],
    abilityFor: (subject) => createAbility(permissions, subject),
    withAudit: (hook) => createPermissions<TPolicy, TInstances>(policy, compiled, hook),
  };

  return permissions;
}

function applyTenantGuard(
  subject: Subject,
  target: unknown,
  compiled: CompiledPolicy,
): Decision | undefined {
  const outcome = evaluateTenantGuard(
    subject,
    target as ResourceInstance | undefined,
    compiled.options,
  );
  if (outcome.kind === 'tenant_mismatch') {
    return makeDecision(false, 'tenant_mismatch');
  }
  if (outcome.kind === 'cross_tenant_disallowed') {
    return makeDecision(false, 'cross_tenant_disallowed');
  }
  return undefined;
}

function expandRoles(
  roles: readonly string[],
  compiled: CompiledPolicy,
): readonly string[] {
  return compiled.roleGraph.expand(roles);
}

function buildError(decision: Decision, args: { subject: Subject; resource: string; action: string }): PermissionError {
  if (decision.reason === 'tenant_mismatch' || decision.reason === 'cross_tenant_disallowed') {
    return new TenantMismatchError({
      decision,
      subject: args.subject,
      resource: args.resource,
      action: args.action,
    });
  }
  return new PermissionError({
    decision,
    subject: args.subject,
    resource: args.resource,
    action: args.action,
  });
}

function buildAuditEvent(
  args: { subject: Subject; resource: unknown; action: unknown; target?: unknown },
  decision: Decision,
  compiled: CompiledPolicy,
): AuditEvent {
  const event: { -readonly [K in keyof AuditEvent]: AuditEvent[K] } = {
    subject: args.subject,
    action: args.action as string,
    resource: args.resource as string,
    decision,
    timestamp: new Date().toISOString(),
  };
  if (args.target !== undefined) event.target = args.target as ResourceInstance;
  if (args.subject.tenantId !== undefined) event.tenantId = args.subject.tenantId;
  if (args.subject.crossTenant === true && compiled.options.allowCrossTenant === true) {
    event.crossTenant = true;
  }
  if (compiled.id !== undefined) event.policyId = compiled.id;
  return event;
}

function runAuditFireAndForget(
  audit: AuditHook | undefined,
  args: { subject: Subject; resource: unknown; action: unknown; target?: unknown },
  decision: Decision,
  compiled: CompiledPolicy,
): void {
  if (!audit) return;
  const mode = compiled.options.auditFailureMode ?? 'log';
  try {
    const result = audit(buildAuditEvent(args, decision, compiled));
    if (result instanceof Promise) {
      result.catch((cause: unknown) => handleAuditFailure(mode, cause));
    }
  } catch (cause) {
    handleAuditFailure(mode, cause);
  }
}

async function runAuditAwait(
  audit: AuditHook | undefined,
  args: { subject: Subject; resource: unknown; action: unknown; target?: unknown },
  decision: Decision,
  compiled: CompiledPolicy,
): Promise<void> {
  if (!audit) return;
  const mode = compiled.options.auditFailureMode ?? 'log';
  try {
    await audit(buildAuditEvent(args, decision, compiled));
  } catch (cause) {
    handleAuditFailure(mode, cause);
  }
}

async function runAuditAwaitWithFailureMode(
  audit: AuditHook | undefined,
  args: { subject: Subject; resource: unknown; action: unknown; target?: unknown },
  decision: Decision,
  compiled: CompiledPolicy,
): Promise<Decision> {
  if (!audit) return decision;
  const mode = compiled.options.auditFailureMode ?? 'log';
  try {
    await audit(buildAuditEvent(args, decision, compiled));
    return decision;
  } catch (cause) {
    if (mode === 'log') {
      warnOnce(
        'audit-failed',
        '[@authkit/permissions] Audit hook threw — swallowing per auditFailureMode="log".',
        cause,
      );
      return decision;
    }
    if (mode === 'deny') {
      return makeDecision(false, 'condition_threw');
    }
    throw new AuditError('Audit hook threw or rejected.', cause);
  }
}

function handleAuditFailure(mode: 'log' | 'throw' | 'deny', cause: unknown): void {
  if (mode === 'log') {
    warnOnce(
      'audit-failed',
      '[@authkit/permissions] Audit hook threw — swallowing per auditFailureMode="log".',
      cause,
    );
    return;
  }
  if (mode === 'throw') {
    throw new AuditError('Audit hook threw or rejected.', cause);
  }
  // 'deny' for the sync path: we cannot retroactively change a returned
  // decision, so we still log to surface the failure. `checkAsync()`'s
  // dedicated handler enforces the deny verdict before returning.
  warnOnce(
    'audit-failed-sync-deny',
    '[@authkit/permissions] Audit hook threw under auditFailureMode="deny" in a sync check; switch to checkAsync() for fail-closed semantics.',
    cause,
  );
}
