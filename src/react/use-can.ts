import * as React from 'react';
import type { CheckArgs } from '../types/context.js';
import type { InferActions, InferResources } from '../types/inference.js';
import type { PolicySpec } from '../types/policy.js';
import { PermissionContext } from './provider.js';

/**
 * Inputs to `useCan` — same shape as `enforcer.check` minus the subject
 * (the context provides it). Keeping a single shape across server +
 * client kills the `(action, resource)` vs `(resource, action)` confusion
 * called out in plan Review 1 #2.
 */
export type UseCanArgs<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> = Omit<CheckArgs<P, R, A>, 'subject'>;

/**
 * Authorisation hook — returns `true` once the enforcer's async `check`
 * resolves with allow.
 *
 * Optimistically returns `false` on the first render so the UI can render
 * a disabled state immediately; updates to `true` once the check resolves.
 * Errors during `check` (e.g. `TENANT_REQUIRED`) propagate so React's
 * error boundary can surface them.
 *
 * @example
 *   const allowed = useCan({ resource: 'document', action: 'update', data: doc });
 *   <button disabled={!allowed}>Update</button>
 */
export function useCan<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(args: UseCanArgs<P, R, A>): boolean {
  const ctx = React.useContext(PermissionContext);
  if (ctx === undefined) {
    throw new Error(
      '[authkit/permissions] useCan must be called within <PermissionProvider>.',
    );
  }
  const [allowed, setAllowed] = React.useState(false);
  const [error, setError] = React.useState<unknown>(undefined);
  const argsRef = React.useRef(args);
  argsRef.current = args;

  // Throwing inside a `.catch` handler runs on the microtask queue and
  // produces an `unhandledrejection` — it does NOT reach React's error
  // boundary (the boundary only sees errors thrown during render or in
  // an `errorInfo` flow). Capture the rejection in state and re-throw
  // during render so a parent boundary can intercept.
  if (error !== undefined) throw error;

  React.useEffect(() => {
    let cancelled = false;
    const subjectArg = { ...argsRef.current, subject: ctx.subject } as CheckArgs<P, R, A>;
    ctx.enforcer
      .check(subjectArg)
      .then((next) => {
        if (!cancelled) setAllowed(next);
      })
      .catch((err: unknown) => {
        // Wrap in a function so `setState` does not interpret a function-typed
        // rejection (rare but possible) as an updater callback.
        if (!cancelled) setError(() => err);
      });
    return () => {
      cancelled = true;
    };
  }, [ctx.enforcer, ctx.subject, args.action, args.resource, args.data, args.tenantId]);

  return allowed;
}
