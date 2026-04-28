import { describe, expect, expectTypeOf, it } from 'vitest';
import { createSubject } from '../core/subject.js';
import type { Subject } from '../types/subject.js';

describe('createSubject', () => {
  it('should construct a frozen subject with required fields', () => {
    const s = createSubject({ id: 'u1', roles: ['admin'] as const });
    expect(s.id).toBe('u1');
    expect(s.roles).toEqual(['admin']);
    expect(Object.isFrozen(s)).toBe(true);
  });

  it('should attach tenantId only when provided', () => {
    const s = createSubject({ id: 'u1', roles: [] as const });
    expect(s.tenantId).toBeUndefined();
    const t = createSubject({ id: 'u1', roles: [] as const, tenantId: 't1' });
    expect(t.tenantId).toBe('t1');
  });

  it('should attach attrs only when provided', () => {
    const s = createSubject({ id: 'u1', roles: [] as const });
    expect(s.attrs).toBeUndefined();
    const t = createSubject({
      id: 'u1',
      roles: [] as const,
      attrs: { plan: 'pro' },
    });
    expect(t.attrs).toEqual({ plan: 'pro' });
  });

  it('should preserve role union literally', () => {
    const s = createSubject({ id: 'u', roles: ['admin', 'member'] as const });
    expectTypeOf(s).toMatchTypeOf<Subject<'admin' | 'member'>>();
  });

  it('should throw on mutation of the returned subject', () => {
    const s = createSubject({ id: 'u1', roles: [] as const });
    expect(() => {
      (s as { id: string }).id = 'u2';
    }).toThrow();
  });
});
