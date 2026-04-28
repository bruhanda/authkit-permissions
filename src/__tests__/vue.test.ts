// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import { mount, enableAutoUnmount } from '@vue/test-utils';
import { defineComponent, h, nextTick } from 'vue';
import { Can } from '../vue/can.js';
import {
  PERMISSIONS_INJECTION_KEY,
  createPermissionsPlugin,
} from '../vue/plugin.js';
import { useCan } from '../vue/use-can.js';
import { defineCondition } from '../core/conditions.js';
import { createEnforcer } from '../core/enforcer.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';

const policy = definePolicy({
  roles: { m: {} },
  resources: { d: { actions: ['read', 'update'] } },
  conditions: {
    isOwner: defineCondition(({ subject, resource }) => {
      const r = resource as { ownerId?: string } | undefined;
      return r?.ownerId === subject.id;
    }),
  },
  permissions: { m: { d: { read: true, update: { when: 'isOwner' } } } },
});
const enforcer = createEnforcer(policy);
const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
const plugin = createPermissionsPlugin({ enforcer, subject });

enableAutoUnmount(afterEach);

describe('createPermissionsPlugin', () => {
  it('should provide the binding under PERMISSIONS_INJECTION_KEY', () => {
    let received: unknown;
    const fakeApp = {
      provide(key: symbol, value: unknown) {
        received = { key, value };
        return fakeApp;
      },
    };
    plugin.install(fakeApp);
    expect(received).toEqual({
      key: PERMISSIONS_INJECTION_KEY,
      value: { enforcer, subject },
    });
  });
});

describe('Vue useCan', () => {
  it('should resolve to true for an allowed action', async () => {
    const Probe = defineComponent({
      setup() {
        const can = useCan({ resource: 'd', action: 'read' });
        return () => h('span', { 'data-testid': 'can' }, String(can.value));
      },
    });
    const wrapper = mount(Probe, { global: { plugins: [plugin] } });
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await nextTick();
    expect(wrapper.text()).toBe('true');
  });

  it('should stay false for a denied action', async () => {
    const Probe = defineComponent({
      setup() {
        const can = useCan({
          resource: 'd',
          action: 'update',
          data: { ownerId: 'someone' },
        });
        return () => h('span', { 'data-testid': 'can' }, String(can.value));
      },
    });
    const wrapper = mount(Probe, { global: { plugins: [plugin] } });
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await nextTick();
    expect(wrapper.text()).toBe('false');
  });

  it('should throw when no plugin is registered', () => {
    const Probe = defineComponent({
      setup() {
        useCan({ resource: 'd', action: 'read' });
        return () => h('span');
      },
    });
    expect(() => mount(Probe)).toThrow(/createPermissionsPlugin/);
  });
});

describe('Vue <Can>', () => {
  it('should render the default slot when allowed', async () => {
    const wrapper = mount(Can, {
      props: { resource: 'd', action: 'read' },
      slots: { default: () => h('span', { 'data-testid': 'ok' }, 'visible') },
      global: { plugins: [plugin] },
    });
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await nextTick();
    expect(wrapper.html()).toContain('visible');
  });

  it('should render the fallback slot when denied', async () => {
    const wrapper = mount(Can, {
      props: {
        resource: 'd',
        action: 'update',
        data: { ownerId: 'other' },
      },
      slots: {
        default: () => h('span', 'allowed'),
        fallback: () => h('span', { 'data-testid': 'fb' }, 'denied'),
      },
      global: { plugins: [plugin] },
    });
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await nextTick();
    expect(wrapper.html()).toContain('denied');
    expect(wrapper.html()).not.toContain('allowed');
  });

  it('should render nothing when denied and no fallback is supplied', async () => {
    const wrapper = mount(Can, {
      props: {
        resource: 'd',
        action: 'update',
        data: { ownerId: 'other' },
      },
      slots: { default: () => h('span', 'allowed') },
      global: { plugins: [plugin] },
    });
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await nextTick();
    expect(wrapper.html()).not.toContain('allowed');
  });
});
