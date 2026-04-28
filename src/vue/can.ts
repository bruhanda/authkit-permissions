import { defineComponent, h, type PropType, type VNode } from 'vue';
import type { CheckArgs } from '../types/context.js';
import type { PolicySpec } from '../types/policy.js';
import { useCan } from './use-can.js';

/**
 * Vue 3 SFC equivalent of the React `<Can>` gate.
 *
 * Renders the default slot when allowed, the `fallback` slot otherwise.
 * Props mirror `enforcer.check` minus the subject (taken from the plugin
 * injection).
 *
 * @example
 *   <Can resource="document" action="delete" :data="doc">
 *     <DeleteButton />
 *     <template #fallback><Disabled /></template>
 *   </Can>
 */
export const Can = defineComponent({
  name: 'AuthkitCan',
  props: {
    action: { type: String as PropType<string>, required: true },
    resource: { type: String as PropType<string>, required: true },
    data: { type: Object as PropType<Record<string, unknown> | undefined>, default: undefined },
    tenantId: { type: String as PropType<string | undefined>, default: undefined },
    allowCrossTenant: { type: Boolean, default: false },
  },
  setup(props, { slots }) {
    const allowed = useCan(props as unknown as Omit<CheckArgs<PolicySpec, never, never>, 'subject'>);
    return (): VNode | null => {
      if (allowed.value) return h('div', { style: 'display: contents' }, slots.default?.());
      const fallback = slots.fallback?.();
      return fallback === undefined ? null : h('div', { style: 'display: contents' }, fallback);
    };
  },
});
