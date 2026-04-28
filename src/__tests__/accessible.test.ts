import { describe, expect, it } from 'vitest';
import { computeAccessibleFilter } from '../core/accessible.js';
import { defineCondition } from '../core/conditions.js';
import { definePolicy } from '../core/policy.js';
import { buildRoleClosure } from '../core/role-graph.js';
import { createSubject } from '../core/subject.js';
import type { ConditionMap } from '../core/evaluator.js';

const ownerCond = defineCondition(({ subject, resource }) => {
  const r = resource as { ownerId?: string } | undefined;
  return r?.ownerId === subject.id;
}, {
  filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }),
});

const tenantCond = defineCondition(({ subject, resource }) => {
  const r = resource as { tenantId?: string } | undefined;
  return r?.tenantId === subject.tenantId;
}, {
  filter: (subject) => ({ kind: 'eq', field: 'tenantId', value: subject.tenantId }),
});

const opaqueCond = defineCondition(() => true);

describe('computeAccessibleFilter', () => {
  it('should return false when resource has no rules', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      permissions: {},
    });
    const closure = buildRoleClosure(policy.spec);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, {}, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({ kind: 'false' });
  });

  it('should return false when bucket exists but no rules for action', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read', 'update'] } },
      permissions: { m: { d: ['read'] } },
    });
    const closure = buildRoleClosure(policy.spec);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, {}, undefined, {
      subject,
      resource: 'd',
      action: 'update',
    });
    expect(ast).toEqual({ kind: 'false' });
  });

  it('should return true for unconditional grant', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      permissions: { m: { d: ['read'] } },
    });
    const closure = buildRoleClosure(policy.spec);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, {}, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({ kind: 'true' });
  });

  it('should lower hinted condition into eq', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { isOwner: ownerCond },
      permissions: { m: { d: { read: { when: 'isOwner' } } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const conditions: ConditionMap = { isOwner: ownerCond };
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, conditions, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({ kind: 'eq', field: 'ownerId', value: 'u' });
  });

  it('should lower allOf to and()', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { isOwner: ownerCond, sameTenant: tenantCond },
      permissions: { m: { d: { read: { allOf: ['isOwner', 'sameTenant'] } } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const conditions: ConditionMap = { isOwner: ownerCond, sameTenant: tenantCond };
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, conditions, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({
      kind: 'and',
      nodes: [
        { kind: 'eq', field: 'ownerId', value: 'u' },
        { kind: 'eq', field: 'tenantId', value: 't1' },
      ],
    });
  });

  it('should lower anyOf to or()', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { isOwner: ownerCond, sameTenant: tenantCond },
      permissions: { m: { d: { read: { anyOf: ['isOwner', 'sameTenant'] } } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const conditions: ConditionMap = { isOwner: ownerCond, sameTenant: tenantCond };
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, conditions, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({
      kind: 'or',
      nodes: [
        { kind: 'eq', field: 'ownerId', value: 'u' },
        { kind: 'eq', field: 'tenantId', value: 't1' },
      ],
    });
  });

  it('should lower not over hinted condition', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { isOwner: ownerCond },
      permissions: { m: { d: { read: { not: 'isOwner' } } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const conditions: ConditionMap = { isOwner: ownerCond };
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, conditions, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({
      kind: 'not',
      node: { kind: 'eq', field: 'ownerId', value: 'u' },
    });
  });

  it('should simplify not(true) to false and not(false) to true', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      permissions: { m: { d: { read: { not: { allOf: [] } } } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, {}, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    // empty allOf simplifies to true → not(true) → false
    expect(ast).toEqual({ kind: 'false' });
  });

  it('should mark unhinted conditions as opaque', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { simple: opaqueCond },
      permissions: { m: { d: { read: { when: 'simple' } } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const conditions: ConditionMap = { simple: opaqueCond };
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, conditions, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({ kind: 'opaque', conditionName: 'simple' });
  });

  it('should mark missing condition as opaque', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      conditions: { simple: opaqueCond },
      permissions: { m: { d: { read: { when: 'simple' } } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, {}, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({ kind: 'opaque', conditionName: 'simple' });
  });

  it('should OR exact-action and wildcard rules together', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      permissions: { m: { d: { read: true, '*': true } } },
    });
    const closure = buildRoleClosure(policy.spec);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, {}, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({ kind: 'true' });
  });

  it('should accept a precomputed effective table', () => {
    const policy = definePolicy({
      roles: { m: {} },
      resources: { d: { actions: ['read'] } },
      permissions: { m: { d: ['read'] } },
    });
    const closure = buildRoleClosure(policy.spec);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    const ast = computeAccessibleFilter(policy.spec, closure, {}, undefined, {
      subject,
      resource: 'd',
      action: 'read',
    });
    expect(ast).toEqual({ kind: 'true' });
  });
});
