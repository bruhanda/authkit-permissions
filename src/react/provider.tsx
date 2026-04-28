import * as React from 'react';
import type { Enforcer } from '../core/enforcer.js';
import type { PolicySpec } from '../types/policy.js';
import type { Subject } from '../types/subject.js';
import type { AnyPermissionContext, PermissionContextValue } from './context.js';

/**
 * Internal singleton context — module-scoped so all hooks/components share
 * the same React context instance. Cast to `unknown` then to the typed
 * shape so the provider can accept any `Enforcer<P>`.
 */
const PermissionContextRaw = React.createContext<PermissionContextValue<PolicySpec> | undefined>(
  undefined,
);
PermissionContextRaw.displayName = 'authkit/PermissionContext';

export const PermissionContext = PermissionContextRaw as unknown as AnyPermissionContext;

/**
 * Props accepted by `<PermissionProvider>`.
 */
export interface PermissionProviderProps<P extends PolicySpec> {
  readonly enforcer: Enforcer<P>;
  readonly subject: Subject;
  readonly children?: React.ReactNode;
}

/**
 * Mount near the React tree's root once `subject` is known. Memoises the
 * context value so a stable `enforcer + subject` pair doesn't trigger
 * re-renders on every parent update.
 *
 * `'use client'` — must run in a client component on Next.js App Router.
 */
export function PermissionProvider<P extends PolicySpec>(
  props: PermissionProviderProps<P>,
): React.ReactElement {
  const value = React.useMemo<PermissionContextValue<P>>(
    () => ({ enforcer: props.enforcer, subject: props.subject }),
    [props.enforcer, props.subject],
  );
  return React.createElement(
    PermissionContextRaw.Provider,
    { value: value as unknown as PermissionContextValue<PolicySpec> },
    props.children,
  );
}
