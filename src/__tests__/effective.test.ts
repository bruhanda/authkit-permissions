import { describe, expect, it } from 'vitest';
import {
  buildEffectiveTable,
  expandResourcePermissions,
  isRuleObject,
} from '../core/effective.js';
import { buildRoleClosure } from '../core/role-graph.js';
import type { PolicySpec } from '../types/policy.js';

describe('isRuleObject', () => {
  it('should return true for a { rule } wrapper', () => {
    expect(isRuleObject({ rule: true })).toBe(true);
    expect(isRuleObject({ rule: { when: 'x' }, priority: 5 })).toBe(true);
  });

  it('should return false for a bare RuleDef', () => {
    expect(isRuleObject(true)).toBe(false);
    expect(isRuleObject({ when: 'x' })).toBe(false);
    expect(isRuleObject({ allOf: ['x'] })).toBe(false);
    expect(isRuleObject({ anyOf: ['x'] })).toBe(false);
    expect(isRuleObject({ not: 'x' })).toBe(false);
  });

  it('should return false for non-objects', () => {
    expect(isRuleObject(null)).toBe(false);
    expect(isRuleObject('rule')).toBe(false);
    expect(isRuleObject(42)).toBe(false);
  });
});

describe('expandResourcePermissions', () => {
  it('should expand a string array to per-action rules', () => {
    const out = expandResourcePermissions(['read', 'update']);
    expect(out).toEqual([
      { action: 'read', rule: true, priority: 0 },
      { action: 'update', rule: true, priority: 0 },
    ]);
  });

  it('should collapse to single wildcard entry when array contains *', () => {
    const out = expandResourcePermissions(['read', '*', 'update']);
    expect(out).toEqual([{ action: '*', rule: true, priority: 0 }]);
  });

  it('should deduplicate repeated actions in array form', () => {
    const out = expandResourcePermissions(['read', 'read', 'update']);
    expect(out).toEqual([
      { action: 'read', rule: true, priority: 0 },
      { action: 'update', rule: true, priority: 0 },
    ]);
  });

  it('should expand object form with bare rules', () => {
    const out = expandResourcePermissions({ read: true, update: { when: 'isOwner' } });
    expect(out).toEqual([
      { action: 'read', rule: true, priority: 0 },
      { action: 'update', rule: { when: 'isOwner' }, priority: 0 },
    ]);
  });

  it('should expand object form with RuleObject (priority + rule)', () => {
    const out = expandResourcePermissions({
      delete: { rule: { when: 'isOwner' }, priority: 5 },
    });
    expect(out).toEqual([{ action: 'delete', rule: { when: 'isOwner' }, priority: 5 }]);
  });

  it('should default RuleObject priority to 0 when omitted', () => {
    const out = expandResourcePermissions({ delete: { rule: true } });
    expect(out).toEqual([{ action: 'delete', rule: true, priority: 0 }]);
  });

  it('should skip undefined values in object form', () => {
    const out = expandResourcePermissions({ read: true, update: undefined });
    expect(out).toEqual([{ action: 'read', rule: true, priority: 0 }]);
  });
});

describe('buildEffectiveTable', () => {
  const spec: PolicySpec = {
    roles: {
      admin: { extends: ['member'] },
      member: {},
    },
    resources: {
      post: { actions: ['read', 'update', 'delete'] },
    },
    permissions: {
      member: { post: ['read'] },
      admin: { post: { delete: { rule: true, priority: 5 }, update: true } },
    },
  };

  it('should compile rules across the role hierarchy', () => {
    const closure = buildRoleClosure(spec);
    const table = buildEffectiveTable(spec, closure, ['admin']);
    const post = table.get('post');
    expect(post).toBeDefined();
    expect(post!.get('read')?.length).toBe(1);
    expect(post!.get('update')?.length).toBe(1);
    expect(post!.get('delete')?.length).toBe(1);
    expect(post!.get('delete')?.[0]?.priority).toBe(5);
  });

  it('should attribute rules to the role that declared them', () => {
    const closure = buildRoleClosure(spec);
    const table = buildEffectiveTable(spec, closure, ['admin']);
    expect(table.get('post')?.get('read')?.[0]?.grantedBy).toBe('member');
    expect(table.get('post')?.get('update')?.[0]?.grantedBy).toBe('admin');
  });

  it('should ignore unknown roles in the role-set', () => {
    const closure = buildRoleClosure(spec);
    const table = buildEffectiveTable(spec, closure, ['ghost', 'member']);
    expect(table.get('post')?.get('read')?.length).toBe(1);
    expect(table.get('post')?.get('delete')).toBeUndefined();
  });

  it('should sort buckets by priority desc, then declaration order asc', () => {
    const ordered: PolicySpec = {
      roles: { a: {} },
      resources: { post: { actions: ['x'] } },
      permissions: {
        a: {
          post: {
            x: { rule: true, priority: 1 },
          },
        },
      },
    };
    const closure = buildRoleClosure(ordered);
    const table = buildEffectiveTable(ordered, closure, ['a']);
    expect(table.get('post')?.get('x')?.length).toBe(1);
  });

  it('should skip undefined permissions blocks', () => {
    const sp: PolicySpec = {
      roles: { a: {} },
      resources: { post: { actions: ['read'] } },
      permissions: { a: undefined },
    };
    const closure = buildRoleClosure(sp);
    const table = buildEffectiveTable(sp, closure, ['a']);
    expect(table.size).toBe(0);
  });
});
