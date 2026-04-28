import { describe, expect, it } from 'vitest';
import { defineCondition } from '../core/conditions.js';
import { definePolicy } from '../core/policy.js';
import { PermissionError } from '../errors/base.js';

describe('definePolicy', () => {
  it('should produce a frozen, branded policy handle', () => {
    const policy = definePolicy({
      roles: { admin: {} },
      resources: { post: { actions: ['read'] } },
      permissions: { admin: { post: ['read'] } },
    });
    expect(policy.__brand).toBe('authkit/policy');
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.spec)).toBe(true);
    expect(Object.isFrozen(policy.spec.roles)).toBe(true);
  });

  it('should accept role inheritance and validate the closure at definition time', () => {
    const policy = definePolicy({
      roles: { admin: { extends: ['member'] }, member: {} },
      resources: { post: { actions: ['read'] } },
      permissions: { admin: { post: ['read'] }, member: {} },
    });
    expect(policy.spec.roles.admin?.extends).toEqual(['member']);
  });

  it('should accept policy with a version stamp', () => {
    const policy = definePolicy({
      version: 'v1.2.3',
      roles: { admin: {} },
      resources: { post: { actions: ['read'] } },
      permissions: { admin: { post: ['read'] } },
    });
    expect(policy.spec.version).toBe('v1.2.3');
  });

  it('should throw INVALID_POLICY when spec is not an object', () => {
    expect(() => definePolicy(null as never)).toThrow(PermissionError);
    expect(() => definePolicy('bad' as never)).toThrow(PermissionError);
  });

  it('should throw INVALID_POLICY when roles is missing', () => {
    expect(() =>
      definePolicy({
        resources: { post: { actions: ['read'] } },
        permissions: {},
      } as never),
    ).toThrow(/roles/);
  });

  it('should throw INVALID_POLICY when resources is missing', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        permissions: {},
      } as never),
    ).toThrow(/resources/);
  });

  it('should throw INVALID_POLICY when permissions is missing', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: {},
      } as never),
    ).toThrow(/permissions/);
  });

  it('should throw INVALID_POLICY when a resource lacks actions array', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: { post: {} as never },
        permissions: {},
      } as never),
    ).toThrow(/actions/);
  });

  it('should throw INVALID_POLICY when conditions is not an object', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: {},
        conditions: 'bad' as never,
        permissions: {},
      } as never),
    ).toThrow(/conditions/);
  });

  it('should throw INVALID_POLICY when a condition is not a function', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: {},
        conditions: { bad: 'no' as never },
        permissions: {},
      } as never),
    ).toThrow(/Condition/);
  });

  it('should throw UNKNOWN_ROLE when permissions reference unknown role', () => {
    try {
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { ghost: { post: ['read'] } },
      } as never);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      expect((err as PermissionError).code).toBe('UNKNOWN_ROLE');
    }
  });

  it('should not let prototype keys ("toString") bypass the unknown-role check', () => {
    try {
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { toString: { post: ['read'] } },
      } as never);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as PermissionError).code).toBe('UNKNOWN_ROLE');
    }
  });

  it('should throw INVALID_POLICY when permissions[role] is not an object', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { admin: 'bad' as never },
      } as never),
    ).toThrow(/role/);
  });

  it('should throw UNKNOWN_RESOURCE when permissions reference unknown resource', () => {
    try {
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { admin: { ghost: ['read'] as never } } as never,
      } as never);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as PermissionError).code).toBe('UNKNOWN_RESOURCE');
    }
  });

  it('should throw UNKNOWN_ACTION when array form contains undeclared action', () => {
    try {
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { admin: { post: ['burn'] as never } } as never,
      } as never);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as PermissionError).code).toBe('UNKNOWN_ACTION');
    }
  });

  it('should throw UNKNOWN_ACTION when object form contains undeclared action', () => {
    try {
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { admin: { post: { burn: true } as never } } as never,
      } as never);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as PermissionError).code).toBe('UNKNOWN_ACTION');
    }
  });

  it('should throw INVALID_POLICY when permissions for a resource is not array or object', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { admin: { post: 'bad' as never } } as never,
      } as never),
    ).toThrow(PermissionError);
  });

  it('should throw UNKNOWN_CONDITION when a rule references undefined condition', () => {
    try {
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        conditions: {},
        permissions: {
          admin: { post: { read: { when: 'isOwner' as never } } as never },
        } as never,
      } as never);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as PermissionError).code).toBe('UNKNOWN_CONDITION');
    }
  });

  it('should accept the wildcard action key', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { admin: { post: ['*'] } },
      }),
    ).not.toThrow();
  });

  it('should accept policy with valid conditions', () => {
    const policy = definePolicy({
      roles: { admin: {} },
      resources: { post: { actions: ['read'] } },
      conditions: {
        isOwner: defineCondition(() => true),
      },
      permissions: {
        admin: { post: { read: { when: 'isOwner' } } },
      },
    });
    expect(policy.spec.conditions?.isOwner).toBeDefined();
  });

  it('should propagate ROLE_CYCLE from buildRoleClosure', () => {
    try {
      definePolicy({
        roles: { a: { extends: ['b'] }, b: { extends: ['a'] } },
        resources: {},
        permissions: {},
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as PermissionError).code).toBe('ROLE_CYCLE');
    }
  });

  it('should skip undefined role permissions blocks without erroring', () => {
    expect(() =>
      definePolicy({
        roles: { admin: {} },
        resources: { post: { actions: ['read'] } },
        permissions: { admin: undefined } as never,
      } as never),
    ).not.toThrow();
  });
});
