import type {
  ConditionEntry,
  TaggedAsyncCondition,
  TaggedSyncCondition,
} from '../types/condition.js';
import type {
  PolicySpec,
  ResourceDef,
  ResourcePermissions,
  RoleDef,
  RuleDef,
} from '../types/policy.js';

/**
 * Mutable, write-only state held by the fluent builder.
 *
 * Once `build()` is called, the state is converted to a frozen
 * `PolicySpec` and handed to `definePolicy()` for validation. The state
 * itself is never re-used after build.
 */
export interface BuilderState {
  version?: string;
  roles: Record<string, RoleDef>;
  resources: Record<string, ResourceDef>;
  conditions: Record<string, ConditionEntry>;
  permissions: Record<string, Record<string, ResourcePermissions<ResourceDef, string>>>;
}

/** Fresh, empty builder state. */
export function emptyState(): BuilderState {
  return {
    roles: {},
    resources: {},
    conditions: {},
    permissions: {},
  };
}

/** Inputs accepted by `.permit()` — same shape as the literal form. */
export type PermitRule = RuleDef | true;

export type SyncOrAsyncCondition = TaggedSyncCondition | TaggedAsyncCondition;

/** Snapshot the builder state into a frozen `PolicySpec`. */
export function snapshot(state: BuilderState): PolicySpec {
  return {
    ...(state.version === undefined ? {} : { version: state.version }),
    roles: state.roles,
    resources: state.resources,
    conditions: state.conditions,
    permissions: state.permissions,
  };
}
