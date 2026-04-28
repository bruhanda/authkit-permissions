import { PermissionError } from '../errors/base.js';
import { ERROR_CODES } from '../errors/codes.js';
import type {
  AuditEvent,
  AuditHook,
  AuditReason,
} from '../types/audit.js';
import type { ConditionArgs, ConditionEntry } from '../types/condition.js';
import type { CheckArgs } from '../types/context.js';
import type {
  EffectivePermissions,
  CompiledRule as PublicCompiledRule,
} from '../types/effective.js';
import type { FilterAst } from '../types/filter.js';
import type {
  InferActions,
  InferConditionMap,
  InferResources,
  InferRoles,
} from '../types/inference.js';
import type { Policy, PolicySpec, RuleDef } from '../types/policy.js';
import type { Decision } from '../types/result.js';
import type { Subject } from '../types/subject.js';
import { isDev } from '../utils/env.js';
import { computeAccessibleFilter } from './accessible.js';
import {
  type CompiledEntry,
  type EffectiveTable,
  buildEffectiveTable,
} from './effective.js';
import {
  type ConditionMap,
  type EvalContext,
  type RuleEvalState,
  evalRuleAsync,
  evalRuleSync,
} from './evaluator.js';
import { actionMatches } from './matcher.js';
import { LRU } from './memo.js';
import { buildRoleClosure } from './role-graph.js';

/**
 * Runtime configuration for an enforcer instance.
 *
 * The enforcer is otherwise stateless apart from the LRU memoising the
 * effective-permission table. Safe to construct once at module load and
 * reuse across requests in any runtime (Node, Edge, Workers).
 */
export interface EnforcerOptions<P extends PolicySpec> {
  /** Replace or extend conditions defined in the policy (e.g. for tests). */
  readonly conditions?: Partial<InferConditionMap<P>>;
  /** Audit hook called after every check. */
  readonly audit?: AuditHook;
  /** LRU capacity for the effective-permissions table. Default 256. */
  readonly cacheSize?: number;
  /**
   * Throw `PermissionError(TENANT_REQUIRED)` when a check is performed
   * without a `tenantId` on the subject. Default `true`.
   */
  readonly strictTenant?: boolean;
  /**
   * Behaviour when an audit hook throws or rejects. See plan §9.4.1.
   *
   *  - `'log'`   (default) — capture to `console.error`, decision unchanged.
   *  - `'throw'` — re-throw after the decision so a global error handler
   *                surfaces the broken pipeline.
   *  - `'deny'`  — fail closed: returns `false` and emits a synthetic
   *                `AUDIT_FAILED` event. Recommended for SOC2 customers.
   */
  readonly auditFailureMode?: 'log' | 'throw' | 'deny';
  /**
   * Edge-runtime escape hatch. Workers terminates the request context as
   * soon as `Response` is returned; pending microtasks are not guaranteed
   * to run. Adapters wire `ctx.waitUntil` here so audit promises survive.
   */
  readonly waitUntil?: (p: Promise<unknown>) => void;
}

/**
 * Per-request decision engine bound to a frozen policy.
 *
 * All methods accept a single `CheckArgs` object so the call shape is
 * identical across `check`, `enforce`, `explain`, and the React/Vue
 * `useCan` hooks — no `(action, resource)` vs `(resource, action)`
 * confusion (plan Review 1 #2).
 */
export interface Enforcer<P extends PolicySpec> {
  /**
   * Allow / deny decision with full type-safety on action and resource.
   *
   * Always returns a Promise — async by design so the audit hook always
   * has a real awaitable boundary (Workers-safe). The previous
   * `boolean | Promise<boolean>` union was unsafe (a forgotten `await`
   * resolved to a truthy object and silently granted access).
   *
   * @returns `true` when the action is allowed.
   * @throws {@link PermissionError} `TENANT_REQUIRED` under `strictTenant`
   *   when `subject.tenantId` is missing.
   *
   * @example
   *   if (await enforcer.check({ subject, resource: 'document', action: 'read' })) { ... }
   */
  check<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<boolean>;

  /**
   * Synchronous fast-path. Throws `ASYNC_CONDITION_IN_SYNC_PATH` when a
   * matching rule references an async (or untagged) condition — surface
   * the bug at call time instead of via a silent allow / deny.
   */
  checkSync<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): boolean;

  /**
   * Same as `check` but throws `PermissionError(FORBIDDEN)` on deny —
   * convenient at API boundaries to short-circuit handlers without
   * branching.
   *
   * @throws {@link PermissionError} `FORBIDDEN` on deny.
   * @example
   *   await enforcer.enforce({ subject, resource: 'document', action: 'delete', data: doc });
   */
  enforce<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<void>;

  /**
   * Inspectable explain — returns the decision plus the matching rule's
   * granting role and condition. Designed for audit logs and tests, not
   * for hot paths.
   */
  explain<R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<Decision<P, R, A>>;

  /**
   * Deeply-readonly view of effective permissions for a role-set.
   * No defensive deep-clone — `Readonly<...>` plus a frozen source is
   * sufficient and avoids bytes the deep-clone path would burn.
   */
  permissionsOf(
    roles: ReadonlyArray<InferRoles<P>>,
  ): Readonly<EffectivePermissions<P>>;

  /**
   * Lower a `(subject, resource, action)` triple into a `FilterAst`
   * suitable for SQL/Mongo `where` clauses (plan §2.5).
   *
   * Conditions without a filter hint emit `{ kind: 'opaque', conditionName }`
   * — translators are expected to treat them as match-all and the
   * application performs a post-fetch check.
   */
  accessibleBy<R extends InferResources<P>, A extends InferActions<P, R>>(args: {
    readonly subject: Subject<InferRoles<P>>;
    readonly resource: R;
    readonly action: A;
  }): FilterAst;

  /** The frozen policy this enforcer was created from. */
  readonly policy: Policy<P>;
}

/**
 * Bind a frozen policy to runtime concerns and return a stateless enforcer.
 *
 * @param policy - return value of `definePolicy(spec)`.
 * @param options - audit, cache size, tenant strictness, audit failure mode.
 * @returns a new `Enforcer<P>` instance.
 *
 * @example
 *   export const enforcer = createEnforcer(policy, {
 *     audit: (event) => logger.info({ msg: 'authz', ...event }),
 *     auditFailureMode: 'log',
 *   });
 */
export function createEnforcer<P extends PolicySpec>(
  policy: Policy<P>,
  options: EnforcerOptions<P> = {},
): Enforcer<P> {
  const closure = buildRoleClosure(policy.spec);
  const conditions: ConditionMap = {
    ...((policy.spec.conditions ?? {}) as ConditionMap),
    ...((options.conditions ?? {}) as ConditionMap),
  };
  const cache = new LRU<EffectiveTable>(Math.max(1, options.cacheSize ?? 256));
  const audit = options.audit;
  const auditFailureMode = options.auditFailureMode ?? 'log';
  const strictTenant = options.strictTenant ?? true;
  const waitUntil = options.waitUntil;

  const tableFor = (roles: ReadonlyArray<string>): EffectiveTable => {
    const key = sortedKey(roles);
    const hit = cache.get(key);
    if (hit !== undefined) return hit;
    const table = buildEffectiveTable(policy.spec, closure, roles);
    cache.set(key, table);
    return table;
  };

  const guardSubject = <R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): { effectiveTenant: string | undefined; crossTenant: boolean; preReason?: AuditReason } => {
    const subject = args.subject;
    const subjectTenant = subject.tenantId;
    const argTenant = args.tenantId;
    const targetTenant = argTenant ?? subjectTenant;

    if (strictTenant && (subjectTenant === undefined || subjectTenant === '')) {
      throw new PermissionError(
        ERROR_CODES.TENANT_REQUIRED,
        'Subject is missing tenantId in strictTenant mode',
        { subjectId: subject.id },
      );
    }

    let crossTenant = false;
    if (
      subjectTenant !== undefined &&
      argTenant !== undefined &&
      argTenant !== subjectTenant
    ) {
      const role = subject.roles.find((r) => policy.spec.roles[r]?.crossTenant === true);
      if (args.allowCrossTenant === true && role !== undefined) {
        crossTenant = true;
      } else {
        return {
          effectiveTenant: targetTenant,
          crossTenant: false,
          preReason: 'tenant_mismatch',
        };
      }
    } else if (args.allowCrossTenant === true) {
      const hasRole = subject.roles.some(
        (r) => policy.spec.roles[r]?.crossTenant === true,
      );
      if (!hasRole) {
        return {
          effectiveTenant: targetTenant,
          crossTenant: false,
          preReason: 'cross_tenant_disallowed',
        };
      }
    }

    return { effectiveTenant: targetTenant, crossTenant };
  };

  const buildAuditEvent = (
    args: CheckArgs<P, never, never>,
    decision: 'allow' | 'deny',
    reason: AuditReason,
    effectiveTenant: string | undefined,
    crossTenant: boolean,
    extra?: { grantedBy?: string; conditionName?: string; cause?: unknown; durationMs?: number },
  ): AuditEvent => {
    const event: {
      ts: number;
      version?: string;
      decision: 'allow' | 'deny';
      reason: AuditReason;
      subject: Subject;
      action: string;
      resource: string;
      data?: Readonly<Record<string, unknown>>;
      tenantId?: string;
      crossTenant?: boolean;
      conditionName?: string;
      cause?: unknown;
      grantedBy?: string;
      durationMs?: number;
    } = {
      ts: Date.now(),
      decision,
      reason,
      subject: args.subject,
      action: args.action as string,
      resource: args.resource as string,
    };
    if (policy.spec.version !== undefined) event.version = policy.spec.version;
    if (args.data !== undefined) event.data = args.data as Readonly<Record<string, unknown>>;
    if (effectiveTenant !== undefined) event.tenantId = effectiveTenant;
    if (crossTenant) event.crossTenant = true;
    if (extra?.grantedBy !== undefined) event.grantedBy = extra.grantedBy;
    if (extra?.conditionName !== undefined) event.conditionName = extra.conditionName;
    if (extra?.cause !== undefined) event.cause = extra.cause;
    if (extra?.durationMs !== undefined) event.durationMs = extra.durationMs;
    return event as AuditEvent;
  };

  const emitAudit = async (event: AuditEvent): Promise<{ overrideDeny: boolean }> => {
    if (audit === undefined) return { overrideDeny: false };
    try {
      const result = audit(event);
      if (result instanceof Promise) {
        if (waitUntil !== undefined) {
          waitUntil(result);
        } else {
          await result;
        }
      }
      return { overrideDeny: false };
    } catch (err) {
      if (auditFailureMode === 'throw') throw err;
      if (auditFailureMode === 'deny') {
        const synthetic: AuditEvent = {
          ...event,
          decision: 'deny',
          reason: 'audit_failed',
          cause: err,
        };
        if (isDev()) {
          // eslint-disable-next-line no-console
          console.error('[authkit/permissions] audit hook threw — failing closed', err);
        }
        try {
          const next = audit(synthetic);
          if (next instanceof Promise) {
            if (waitUntil !== undefined) waitUntil(next);
            else await next.catch(() => undefined);
          }
        } catch {
          /* nothing more we can do */
        }
        return { overrideDeny: true };
      }
      // 'log' (default)
      // eslint-disable-next-line no-console
      console.error('[authkit/permissions] audit hook threw', err);
      return { overrideDeny: false };
    }
  };

  const collectCandidates = (
    table: EffectiveTable,
    resource: string,
    action: string,
  ): CompiledEntry[] => {
    const bucket = table.get(resource);
    if (bucket === undefined) return [];
    const out: CompiledEntry[] = [];
    for (const [declared, entries] of bucket) {
      if (actionMatches(declared, action)) out.push(...entries);
    }
    out.sort((a, b) => b.priority - a.priority || a.order - b.order);
    return out;
  };

  const conditionArgsFor = <R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
    effectiveTenant: string | undefined,
  ): ConditionArgs => {
    const out: {
      subject: Subject;
      resource?: Record<string, unknown> | undefined;
      resourceType: string;
      action: string;
      tenantId?: string;
    } = {
      subject: args.subject,
      resourceType: args.resource as string,
      action: args.action as string,
    };
    if (args.data !== undefined) out.resource = args.data as Record<string, unknown>;
    if (effectiveTenant !== undefined) out.tenantId = effectiveTenant;
    return out;
  };

  type Outcome = {
    decision: 'allow' | 'deny';
    reason: AuditReason;
    grantedBy?: string;
    conditionName?: string;
    cause?: unknown;
  };

  const decideFromState = (
    granted: { entry: CompiledEntry } | undefined,
    state: RuleEvalState,
    hadCandidates: boolean,
  ): Outcome => {
    if (granted !== undefined) {
      const out: Outcome = {
        decision: 'allow',
        reason: 'allowed_by_rule',
        grantedBy: granted.entry.grantedBy,
      };
      return out;
    }
    if (!hadCandidates) {
      return { decision: 'deny', reason: 'no_matching_rule' };
    }
    if (state.threwCondition !== undefined) {
      const out: Outcome = {
        decision: 'deny',
        reason: 'condition_threw',
        conditionName: state.threwCondition,
        cause: state.threwCause,
      };
      return out;
    }
    if (state.nonBooleanCondition !== undefined) {
      return {
        decision: 'deny',
        reason: 'non_boolean_condition_result',
        conditionName: state.nonBooleanCondition,
      };
    }
    if (state.failedCondition !== undefined) {
      return {
        decision: 'deny',
        reason: 'condition_failed',
        conditionName: state.failedCondition,
      };
    }
    return { decision: 'deny', reason: 'no_matching_rule' };
  };

  const preDecide = <R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): { ok: boolean; outcome?: Outcome; effectiveTenant: string | undefined; crossTenant: boolean } => {
    const subject = args.subject;
    if (subject.roles.length === 0) {
      return {
        ok: false,
        outcome: { decision: 'deny', reason: 'no_roles' },
        effectiveTenant: subject.tenantId,
        crossTenant: false,
      };
    }
    for (const role of subject.roles) {
      if (!(role in policy.spec.roles)) {
        return {
          ok: false,
          outcome: { decision: 'deny', reason: 'unknown_role_on_subject' },
          effectiveTenant: subject.tenantId,
          crossTenant: false,
        };
      }
    }
    const guard = guardSubject(args);
    if (guard.preReason !== undefined) {
      return {
        ok: false,
        outcome: { decision: 'deny', reason: guard.preReason },
        effectiveTenant: guard.effectiveTenant,
        crossTenant: guard.crossTenant,
      };
    }
    return {
      ok: true,
      effectiveTenant: guard.effectiveTenant,
      crossTenant: guard.crossTenant,
    };
  };

  const evalAllSync = (
    rules: ReadonlyArray<CompiledEntry>,
    ctx: EvalContext,
  ): { match?: CompiledEntry; state: RuleEvalState } => {
    const aggregate: RuleEvalState = {};
    for (const entry of rules) {
      const local: RuleEvalState = {};
      if (evalRuleSync(entry.rule, ctx, local)) return { match: entry, state: local };
      mergeState(aggregate, local);
    }
    return { state: aggregate };
  };

  const evalAllAsync = async (
    rules: ReadonlyArray<CompiledEntry>,
    ctx: EvalContext,
  ): Promise<{ match?: CompiledEntry; state: RuleEvalState }> => {
    const aggregate: RuleEvalState = {};
    for (const entry of rules) {
      const local: RuleEvalState = {};
      const ok = await evalRuleAsync(entry.rule, ctx, local);
      if (ok) return { match: entry, state: local };
      mergeState(aggregate, local);
    }
    return { state: aggregate };
  };

  const dispatchAsync = async <R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): Promise<{ outcome: Outcome; effectiveTenant: string | undefined; crossTenant: boolean }> => {
    const pre = preDecide(args);
    if (!pre.ok) {
      return {
        outcome: pre.outcome as Outcome,
        effectiveTenant: pre.effectiveTenant,
        crossTenant: pre.crossTenant ?? false,
      };
    }
    const candidates = collectCandidates(
      tableFor(args.subject.roles),
      args.resource as string,
      args.action as string,
    );
    if (candidates.length === 0) {
      return {
        outcome: { decision: 'deny', reason: 'no_matching_rule' },
        effectiveTenant: pre.effectiveTenant,
        crossTenant: pre.crossTenant ?? false,
      };
    }
    const ctx: EvalContext = { conditions, args: conditionArgsFor(args, pre.effectiveTenant) };
    const { match, state } = await evalAllAsync(candidates, ctx);
    return {
      outcome: decideFromState(match !== undefined ? { entry: match } : undefined, state, true),
      effectiveTenant: pre.effectiveTenant,
      crossTenant: pre.crossTenant ?? false,
    };
  };

  const dispatchSync = <R extends InferResources<P>, A extends InferActions<P, R>>(
    args: CheckArgs<P, R, A>,
  ): { outcome: Outcome; effectiveTenant: string | undefined; crossTenant: boolean } => {
    const pre = preDecide(args);
    if (!pre.ok) {
      return {
        outcome: pre.outcome as Outcome,
        effectiveTenant: pre.effectiveTenant,
        crossTenant: pre.crossTenant ?? false,
      };
    }
    const candidates = collectCandidates(
      tableFor(args.subject.roles),
      args.resource as string,
      args.action as string,
    );
    if (candidates.length === 0) {
      return {
        outcome: { decision: 'deny', reason: 'no_matching_rule' },
        effectiveTenant: pre.effectiveTenant,
        crossTenant: pre.crossTenant ?? false,
      };
    }
    const ctx: EvalContext = { conditions, args: conditionArgsFor(args, pre.effectiveTenant) };
    const { match, state } = evalAllSync(candidates, ctx);
    return {
      outcome: decideFromState(match !== undefined ? { entry: match } : undefined, state, true),
      effectiveTenant: pre.effectiveTenant,
      crossTenant: pre.crossTenant ?? false,
    };
  };

  const enforcer: Enforcer<P> = {
    policy,

    async check<R extends InferResources<P>, A extends InferActions<P, R>>(
      args: CheckArgs<P, R, A>,
    ): Promise<boolean> {
      const { outcome, effectiveTenant, crossTenant } = await dispatchAsync(args);
      const event = buildAuditEvent(
        args as CheckArgs<P, never, never>,
        outcome.decision,
        outcome.reason,
        effectiveTenant,
        crossTenant,
        outcome,
      );
      const { overrideDeny } = await emitAudit(event);
      if (overrideDeny) return false;
      return outcome.decision === 'allow';
    },

    checkSync<R extends InferResources<P>, A extends InferActions<P, R>>(
      args: CheckArgs<P, R, A>,
    ): boolean {
      const { outcome, effectiveTenant, crossTenant } = dispatchSync(args);
      // Sync path: fire audit but never await — log mode only.
      if (audit !== undefined) {
        const event = buildAuditEvent(
          args as CheckArgs<P, never, never>,
          outcome.decision,
          outcome.reason,
          effectiveTenant,
          crossTenant,
          outcome,
        );
        try {
          const result = audit(event);
          if (result instanceof Promise) {
            if (waitUntil !== undefined) waitUntil(result);
            else result.catch((err) => {
              if (isDev()) {
                // eslint-disable-next-line no-console
                console.error('[authkit/permissions] audit hook rejected (sync path)', err);
              }
            });
          }
        } catch (err) {
          if (auditFailureMode === 'throw') throw err;
          if (auditFailureMode === 'deny') return false;
          // eslint-disable-next-line no-console
          console.error('[authkit/permissions] audit hook threw (sync path)', err);
        }
      }
      return outcome.decision === 'allow';
    },

    async enforce<R extends InferResources<P>, A extends InferActions<P, R>>(
      args: CheckArgs<P, R, A>,
    ): Promise<void> {
      const allowed = await enforcer.check(args);
      if (!allowed) {
        throw new PermissionError(
          ERROR_CODES.FORBIDDEN,
          `Forbidden: ${String(args.action)} on ${String(args.resource)}`,
          {
            subjectId: args.subject.id,
            action: args.action as string,
            resource: args.resource as string,
          },
        );
      }
    },

    async explain<R extends InferResources<P>, A extends InferActions<P, R>>(
      args: CheckArgs<P, R, A>,
    ): Promise<Decision<P, R, A>> {
      const start = nowMs();
      const { outcome, effectiveTenant, crossTenant } = await dispatchAsync(args);
      const durationMs = nowMs() - start;
      const event = buildAuditEvent(
        args as CheckArgs<P, never, never>,
        outcome.decision,
        outcome.reason,
        effectiveTenant,
        crossTenant,
        { ...outcome, durationMs },
      );
      await emitAudit(event);
      const decision: {
        allowed: boolean;
        reason: AuditReason;
        resource: R;
        action: A;
        grantedBy?: string;
        conditionName?: string;
        durationMs?: number;
      } = {
        allowed: outcome.decision === 'allow',
        reason: outcome.reason,
        resource: args.resource,
        action: args.action,
        durationMs,
      };
      if (outcome.grantedBy !== undefined) decision.grantedBy = outcome.grantedBy;
      if (outcome.conditionName !== undefined) decision.conditionName = outcome.conditionName;
      return decision as Decision<P, R, A>;
    },

    permissionsOf(roles: ReadonlyArray<InferRoles<P>>): Readonly<EffectivePermissions<P>> {
      const table = tableFor(roles);
      const out: Record<string, Record<string, ReadonlyArray<PublicCompiledRule<P>>>> = {};
      for (const [resource, bucket] of table) {
        const inner: Record<string, ReadonlyArray<PublicCompiledRule<P>>> = {};
        for (const [action, entries] of bucket) {
          inner[action] = entries.map((entry) => ({
            resource: entry.resource as InferResources<P>,
            action: entry.action,
            rule: entry.rule as RuleDef,
            priority: entry.priority,
            order: entry.order,
            grantedBy: entry.grantedBy as InferRoles<P>,
          })) as ReadonlyArray<PublicCompiledRule<P>>;
        }
        out[resource] = inner;
      }
      return out as Readonly<EffectivePermissions<P>>;
    },

    accessibleBy<R extends InferResources<P>, A extends InferActions<P, R>>(args: {
      readonly subject: Subject<InferRoles<P>>;
      readonly resource: R;
      readonly action: A;
    }): FilterAst {
      return computeAccessibleFilter(
        policy.spec,
        closure,
        conditions,
        tableFor(args.subject.roles),
        args,
      );
    },
  };

  return enforcer;
}

function sortedKey(roles: ReadonlyArray<string>): string {
  return [...new Set(roles)].sort().join('');
}

function mergeState(target: RuleEvalState, source: RuleEvalState): void {
  if (target.threwCondition === undefined && source.threwCondition !== undefined) {
    target.threwCondition = source.threwCondition;
    target.threwCause = source.threwCause;
  }
  if (target.nonBooleanCondition === undefined && source.nonBooleanCondition !== undefined) {
    target.nonBooleanCondition = source.nonBooleanCondition;
  }
  if (source.failedCondition !== undefined) {
    target.failedCondition = source.failedCondition;
  }
}

function nowMs(): number {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}
