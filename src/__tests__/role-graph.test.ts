import { describe, expect, it } from 'vitest';
import { buildRoleClosure } from '../core/role-graph.js';
import { PermissionError } from '../errors/base.js';
import type { PolicySpec } from '../types/policy.js';

const baseSpec = (
  roles: Record<string, { extends?: ReadonlyArray<string> }>,
): PolicySpec => ({
  roles,
  resources: {},
  permissions: {},
});

describe('buildRoleClosure', () => {
  it('should include the role itself in its ancestor set', () => {
    const closure = buildRoleClosure(baseSpec({ admin: {} }));
    expect(closure.ancestorsOf.get('admin')).toEqual(['admin']);
  });

  it('should compute transitive ancestors in dependency order', () => {
    const spec = baseSpec({
      admin: { extends: ['member'] },
      member: { extends: ['viewer'] },
      viewer: {},
    });
    const closure = buildRoleClosure(spec);
    expect(closure.ancestorsOf.get('admin')).toEqual(['admin', 'member', 'viewer']);
    expect(closure.ancestorsOf.get('member')).toEqual(['member', 'viewer']);
    expect(closure.ancestorsOf.get('viewer')).toEqual(['viewer']);
  });

  it('should expand diamond inheritance once', () => {
    const spec = baseSpec({
      admin: { extends: ['editor', 'reviewer'] },
      editor: { extends: ['member'] },
      reviewer: { extends: ['member'] },
      member: {},
    });
    const closure = buildRoleClosure(spec);
    const ancestors = closure.ancestorsOf.get('admin');
    expect(ancestors).toEqual(['admin', 'editor', 'member', 'reviewer']);
  });

  it('should throw ROLE_CYCLE on self-extension', () => {
    expect(() =>
      buildRoleClosure(baseSpec({ admin: { extends: ['admin'] } })),
    ).toThrow(PermissionError);
    try {
      buildRoleClosure(baseSpec({ admin: { extends: ['admin'] } }));
    } catch (err) {
      const pe = err as PermissionError;
      expect(pe.code).toBe('ROLE_CYCLE');
      expect(pe.context).toEqual({ role: 'admin' });
    }
  });

  it('should throw ROLE_CYCLE on transitive cycle', () => {
    const spec = baseSpec({
      a: { extends: ['b'] },
      b: { extends: ['c'] },
      c: { extends: ['a'] },
    });
    try {
      buildRoleClosure(spec);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      const pe = err as PermissionError;
      expect(pe.code).toBe('ROLE_CYCLE');
      expect((pe.context as { cycle: string }).cycle).toContain('->');
    }
  });

  it('should throw UNKNOWN_ROLE when extends references undeclared role', () => {
    try {
      buildRoleClosure(baseSpec({ admin: { extends: ['ghost'] } }));
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      const pe = err as PermissionError;
      expect(pe.code).toBe('UNKNOWN_ROLE');
      expect(pe.context).toEqual({ role: 'admin', parent: 'ghost' });
    }
  });

  it('should support roles with no extends', () => {
    const closure = buildRoleClosure(
      baseSpec({ admin: {}, member: {} }),
    );
    expect(closure.ancestorsOf.size).toBe(2);
    expect(closure.ancestorsOf.get('admin')).toEqual(['admin']);
    expect(closure.ancestorsOf.get('member')).toEqual(['member']);
  });
});
