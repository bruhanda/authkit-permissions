import { inject, ref, watchEffect, type Ref } from 'vue';
import type { CheckArgs } from '../types/context.js';
import type { InferActions, InferResources } from '../types/inference.js';
import type { PolicySpec } from '../types/policy.js';
import { PERMISSIONS_INJECTION_KEY, type PermissionsBinding } from './plugin.js';

/**
 * Vue 3 composable mirroring the React `useCan` shape — returns a
 * `Ref<boolean>` so templates can reactively re-render when permissions
 * change (e.g. role updates pushed via WebSocket).
 *
 * Mirrors the object-form `enforcer.check` argument shape for consistency
 * with server-side calls.
 *
 * @example
 *   const canDelete = useCan({ resource: 'document', action: 'delete', data: doc });
 *   <button :disabled="!canDelete.value">Delete</button>
 */
export function useCan<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(args: Omit<CheckArgs<P, R, A>, 'subject'>): Ref<boolean> {
  const binding = inject<PermissionsBinding<P>>(PERMISSIONS_INJECTION_KEY);
  if (binding === undefined) {
    throw new Error(
      '[authkit/permissions] useCan requires createPermissionsPlugin() registered on the app.',
    );
  }
  const allowed = ref(false);
  watchEffect(() => {
    let cancelled = false;
    binding.enforcer
      .check({ ...args, subject: binding.subject } as CheckArgs<P, R, A>)
      .then((value) => {
        if (!cancelled) allowed.value = value;
      });
    return () => {
      cancelled = true;
    };
  });
  return allowed;
}
