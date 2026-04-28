import type { InferActions, InferResources, InferRoles } from './inference.js';
import type { PolicySpec } from './policy.js';
import type { Subject } from './subject.js';

/**
 * Module-augmentable map from resource name to its instance shape.
 *
 * Consumers extend this in their own code to make `data` strongly-typed at
 * the call site:
 *
 * ```ts
 * declare module '@authkit/permissions' {
 *   interface ResourceDataMap {
 *     document: { id: string; ownerId: string; tenantId: string };
 *   }
 * }
 * ```
 *
 * Resources without an entry fall back to `Record<string, unknown>` so
 * augmentation is gradual.
 */
// biome-ignore lint/suspicious/noEmptyInterface: intentional augmentation point
export interface ResourceDataMap {}

/** Per-resource instance type, narrowed via `ResourceDataMap`. */
export type ResourceData<R extends string> = R extends keyof ResourceDataMap
  ? ResourceDataMap[R]
  : Record<string, unknown>;

/**
 * Inputs to `enforcer.check` / `checkSync` / `enforce` / `explain`.
 *
 * Action and resource are narrowed by the policy literal so typos are a
 * TypeScript error, not a runtime miss. `data` is narrowed via
 * `ResourceDataMap` when the consumer augments it.
 */
export interface CheckArgs<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> {
  /** Caller — must always carry roles and (in `strictTenant` mode) `tenantId`. */
  readonly subject: Subject<InferRoles<P>>;
  /** Action being attempted on `resource`. */
  readonly action: A;
  /** Resource type — string literal must match a declared resource. */
  readonly resource: R;
  /** Optional resource instance for ABAC conditions (ownership, tenancy). */
  readonly data?: ResourceData<R>;
  /**
   * Tenant scope of the check. Defaults to `subject.tenantId`. A different
   * value triggers `TENANT_MISMATCH` unless **both** the role declares
   * `crossTenant: true` AND `allowCrossTenant: true` is passed below.
   */
  readonly tenantId?: string;
  /** Per-call opt-in for cross-tenant access. See `tenantId` above. */
  readonly allowCrossTenant?: boolean;
}
