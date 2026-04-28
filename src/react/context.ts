import type * as React from 'react';
import type { Enforcer } from '../core/enforcer.js';
import type { PolicySpec } from '../types/policy.js';
import type { Subject } from '../types/subject.js';

/**
 * Value carried by the `PermissionContext`. Holds the enforcer and the
 * subject for the current React tree.
 *
 * `undefined` when no `<PermissionProvider>` is mounted — `useCan` throws
 * a developer-friendly error in that case rather than silently denying.
 */
export interface PermissionContextValue<P extends PolicySpec> {
  readonly enforcer: Enforcer<P>;
  readonly subject: Subject;
}

/**
 * React context shared by `<PermissionProvider>`, `useCan` and `<Can>`.
 *
 * Untyped on the policy parameter so the same context can carry any
 * `Enforcer<P>` instance — the typed surface lives on the hooks
 * themselves.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyPermissionContext = React.Context<PermissionContextValue<any> | undefined>;
