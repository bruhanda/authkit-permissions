// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import * as React from 'react';
import { Can } from '../react/can.js';
import { PermissionContext, PermissionProvider } from '../react/provider.js';
import { useCan } from '../react/use-can.js';
import { createEnforcer } from '../core/enforcer.js';
import { defineCondition } from '../core/conditions.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';
import type { Subject } from '../types/subject.js';

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
const allowedSubject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });

afterEach(() => {
  cleanup();
});

describe('PermissionProvider', () => {
  it('should provide enforcer and subject to children via context', () => {
    let received: { enforcer?: unknown; subject?: Subject } | undefined;
    const Probe = (): null => {
      received = React.useContext(PermissionContext);
      return null;
    };
    render(
      <PermissionProvider enforcer={enforcer} subject={allowedSubject}>
        <Probe />
      </PermissionProvider>,
    );
    expect(received?.enforcer).toBe(enforcer);
    expect(received?.subject).toBe(allowedSubject);
  });
});

describe('useCan', () => {
  it('should resolve to true for an allowed action', async () => {
    const Probe = (): React.ReactElement => {
      const can = useCan({ resource: 'd', action: 'read' });
      return <span data-testid="can">{String(can)}</span>;
    };
    render(
      <PermissionProvider enforcer={enforcer} subject={allowedSubject}>
        <Probe />
      </PermissionProvider>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('can').textContent).toBe('true');
    });
  });

  it('should remain false for a denied action', async () => {
    const Probe = (): React.ReactElement => {
      const can = useCan({
        resource: 'd',
        action: 'update',
        data: { ownerId: 'someone-else' },
      });
      return <span data-testid="can">{String(can)}</span>;
    };
    render(
      <PermissionProvider enforcer={enforcer} subject={allowedSubject}>
        <Probe />
      </PermissionProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(screen.getByTestId('can').textContent).toBe('false');
  });

  it('should throw when called without a provider', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const Probe = (): React.ReactElement | null => {
      useCan({ resource: 'd', action: 'read' });
      return null;
    };
    class Boundary extends React.Component<
      { children: React.ReactNode },
      { err?: Error }
    > {
      constructor(props: { children: React.ReactNode }) {
        super(props);
        this.state = {};
      }
      static getDerivedStateFromError(err: Error): { err: Error } {
        return { err };
      }
      override render(): React.ReactNode {
        if (this.state.err) return <span data-testid="err">{this.state.err.message}</span>;
        return this.props.children;
      }
    }
    render(
      <Boundary>
        <Probe />
      </Boundary>,
    );
    expect(screen.getByTestId('err').textContent).toContain('PermissionProvider');
    errorSpy.mockRestore();
  });

  it('should propagate enforcer errors to error boundary', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const noTenantSubject = createSubject({ id: 'u', roles: ['m'] as const });
    const Probe = (): React.ReactElement | null => {
      useCan({ resource: 'd', action: 'read' });
      return null;
    };
    class Boundary extends React.Component<
      { children: React.ReactNode },
      { err?: Error }
    > {
      constructor(props: { children: React.ReactNode }) {
        super(props);
        this.state = {};
      }
      static getDerivedStateFromError(err: Error): { err: Error } {
        return { err };
      }
      override render(): React.ReactNode {
        if (this.state.err) return <span data-testid="err">{this.state.err.message}</span>;
        return this.props.children;
      }
    }
    render(
      <Boundary>
        <PermissionProvider enforcer={enforcer} subject={noTenantSubject}>
          <Probe />
        </PermissionProvider>
      </Boundary>,
    );
    await waitFor(() => {
      expect(screen.queryByTestId('err')).not.toBeNull();
    });
    errorSpy.mockRestore();
  });
});

describe('<Can>', () => {
  it('should render children when allowed', async () => {
    render(
      <PermissionProvider enforcer={enforcer} subject={allowedSubject}>
        <Can resource="d" action="read">
          <span data-testid="ok">visible</span>
        </Can>
      </PermissionProvider>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('ok')).not.toBeNull();
    });
  });

  it('should render fallback when denied', async () => {
    render(
      <PermissionProvider enforcer={enforcer} subject={allowedSubject}>
        <Can
          resource="d"
          action="update"
          data={{ ownerId: 'other' }}
          fallback={<span data-testid="fb">no</span>}
        >
          <span data-testid="ok">yes</span>
        </Can>
      </PermissionProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(screen.getByTestId('fb')).not.toBeNull();
    expect(screen.queryByTestId('ok')).toBeNull();
  });

  it('should render nothing when denied and no fallback is provided', async () => {
    const { container } = render(
      <PermissionProvider enforcer={enforcer} subject={allowedSubject}>
        <Can resource="d" action="update" data={{ ownerId: 'other' }}>
          <span data-testid="ok">yes</span>
        </Can>
      </PermissionProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(container.querySelector('[data-testid="ok"]')).toBeNull();
  });
});
