/**
 * `@authkit/permissions` — lightweight, zero-dependency, TypeScript-first
 * RBAC/ABAC with a multi-tenant context as a first-class citizen.
 *
 * Public entrypoint for the core engine. Adapters, ORM helpers, React, Vue,
 * builder, audit utilities and error class live in subpath exports — see
 * `package.json` `exports` for the full list.
 */

export { definePolicy } from './core/policy.js';
export { createEnforcer } from './core/enforcer.js';
export type { Enforcer, EnforcerOptions } from './core/enforcer.js';
export {
  defineCondition,
  defineAsyncCondition,
  isAsyncCondition,
  isSyncCondition,
} from './core/conditions.js';
export type { ConditionFilterHint } from './core/conditions.js';
export { createSubject } from './core/subject.js';
export { composeAudit } from './audit/hook.js';

export { PermissionError, ERROR_CODES } from './errors/index.js';
export type { ErrorCode } from './errors/index.js';

export type {
  AsyncConditionFn,
  AuditDecision,
  AuditEvent,
  AuditHook,
  AuditReason,
  CheckArgs,
  CompiledRule,
  ConditionArgs,
  ConditionEntry,
  ConditionFn,
  Decision,
  DenyReason,
  EffectivePermissions,
  FilterAst,
  InferActions,
  InferConditionMap,
  InferConditions,
  InferResources,
  InferRoles,
  Policy,
  PolicySpec,
  ResourceData,
  ResourceDataMap,
  ResourceDef,
  ResourcePermissions,
  RoleDef,
  RuleDef,
  RuleObject,
  Subject,
  TaggedAsyncCondition,
  TaggedSyncCondition,
  ValidatePolicy,
} from './types/index.js';
