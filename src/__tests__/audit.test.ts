import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { composeAudit } from '../audit/hook.js';
import { jsonFormatter, tenantHashFormatter } from '../audit/formatter.js';
import { withTiming } from '../audit/timing.js';
import type { AuditEvent } from '../types/audit.js';

const eventBase: AuditEvent = {
  ts: 1700000000000,
  decision: 'allow',
  reason: 'allowed_by_rule',
  subject: { id: 'u1', roles: ['admin'], tenantId: 't1' },
  action: 'read',
  resource: 'document',
  tenantId: 't1',
};

describe('composeAudit', () => {
  it('should return a no-op when no hooks are provided', () => {
    const hook = composeAudit();
    expect(hook(eventBase)).toBeUndefined();
  });

  it('should pass through a single hook unchanged', () => {
    const inner = vi.fn();
    const hook = composeAudit(inner);
    hook(eventBase);
    expect(inner).toHaveBeenCalledWith(eventBase);
  });

  it('should fan out to multiple hooks left-to-right', async () => {
    const order: number[] = [];
    const a = vi.fn(() => {
      order.push(1);
    });
    const b = vi.fn(async () => {
      order.push(2);
    });
    const c = vi.fn(() => {
      order.push(3);
    });
    await composeAudit(a, b, c)(eventBase);
    expect(order).toEqual([1, 2, 3]);
  });

  it('should run subsequent hooks even when one throws and aggregate errors', async () => {
    const a = vi.fn(() => {
      throw new Error('a-fail');
    });
    const b = vi.fn();
    await expect(composeAudit(a, b)(eventBase)).rejects.toBeInstanceOf(Error);
    expect(b).toHaveBeenCalledOnce();
  });

  it('should throw a single error when only one hook fails', async () => {
    const err = new Error('one');
    const failing = (): never => {
      throw err;
    };
    await expect(composeAudit(failing, () => undefined)(eventBase)).rejects.toBe(err);
  });

  it('should throw AggregateError when multiple hooks fail', async () => {
    const a = (): never => {
      throw new Error('a');
    };
    const b = (): never => {
      throw new Error('b');
    };
    const promise = composeAudit(a, b)(eventBase);
    await expect(promise).rejects.toBeInstanceOf(AggregateError);
  });

  it('should accept async rejecting hooks', async () => {
    const a = (): Promise<void> => Promise.reject(new Error('async-bad'));
    const b = vi.fn();
    await expect(composeAudit(a, b)(eventBase)).rejects.toThrow('async-bad');
    expect(b).toHaveBeenCalled();
  });
});

describe('jsonFormatter', () => {
  it('should produce a single-line JSON string', () => {
    const out = jsonFormatter(eventBase);
    expect(out.includes('\n')).toBe(false);
    const parsed = JSON.parse(out);
    expect(parsed.decision).toBe('allow');
    expect(parsed.reason).toBe('allowed_by_rule');
  });

  it('should serialise Error causes as { name, message }', () => {
    const out = jsonFormatter({ ...eventBase, cause: new Error('boom') });
    const parsed = JSON.parse(out);
    expect(parsed.cause).toEqual({ name: 'Error', message: 'boom' });
  });

  it('should serialise bigint values as strings', () => {
    const out = jsonFormatter({
      ...eventBase,
      data: { count: 9007199254740993n as unknown as number },
    });
    const parsed = JSON.parse(out);
    expect(parsed.data.count).toBe('9007199254740993');
  });
});

describe('tenantHashFormatter', () => {
  it('should hash tenantId to 8 hex chars', () => {
    const fmt = tenantHashFormatter();
    const out = fmt(eventBase);
    const parsed = JSON.parse(out);
    expect(parsed.tenantId).toMatch(/^[0-9a-f]{8}$/);
  });

  it('should leave tenantId untouched when undefined', () => {
    const fmt = tenantHashFormatter();
    const evtNoTenant: AuditEvent = {
      ts: eventBase.ts,
      decision: eventBase.decision,
      reason: eventBase.reason,
      subject: eventBase.subject,
      action: eventBase.action,
      resource: eventBase.resource,
    };
    const out = fmt(evtNoTenant);
    const parsed = JSON.parse(out);
    expect(parsed.tenantId).toBeUndefined();
  });

  it('should be deterministic across calls', () => {
    const fmt = tenantHashFormatter();
    expect(fmt(eventBase)).toBe(fmt(eventBase));
  });

  it('should produce different hashes for different tenants', () => {
    const fmt = tenantHashFormatter();
    const a = JSON.parse(fmt({ ...eventBase, tenantId: 'tenant-a' })).tenantId;
    const b = JSON.parse(fmt({ ...eventBase, tenantId: 'tenant-b' })).tenantId;
    expect(a).not.toBe(b);
  });
});

describe('withTiming', () => {
  let debugSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    debugSpy = vi.spyOn(console, 'debug').mockImplementation(() => undefined);
  });
  afterEach(() => {
    debugSpy.mockRestore();
  });

  it('should call the inner hook with the event', async () => {
    const inner = vi.fn();
    const wrapped = withTiming(inner, () => undefined);
    await wrapped(eventBase);
    expect(inner).toHaveBeenCalledWith(eventBase);
  });

  it('should report timing to the supplied sink', async () => {
    const samples: Array<{ ms: number; reason: string; decision: string }> = [];
    const wrapped = withTiming(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }, (s) => samples.push(s));
    await wrapped(eventBase);
    expect(samples).toHaveLength(1);
    expect(samples[0]?.reason).toBe('allowed_by_rule');
    expect(samples[0]?.decision).toBe('allow');
    expect(samples[0]?.ms).toBeGreaterThanOrEqual(0);
  });

  it('should still report timing when the inner hook throws', async () => {
    const samples: Array<{ ms: number }> = [];
    const wrapped = withTiming(() => {
      throw new Error('boom');
    }, (s) => samples.push(s));
    await expect(wrapped(eventBase)).rejects.toThrow('boom');
    expect(samples).toHaveLength(1);
  });

  it('should default the sink to console.debug', async () => {
    const wrapped = withTiming(() => undefined);
    await wrapped(eventBase);
    expect(debugSpy).toHaveBeenCalled();
  });
});
