import { describe, expect, it } from 'vitest';
import { defineCondition } from '../core/conditions.js';
import { createPolicyBuilder } from '../builder/index.js';
import { createSubject } from '../core/subject.js';
import { createEnforcer } from '../core/enforcer.js';

describe('PolicyBuilder', () => {
  it('should assemble a minimal policy', () => {
    const policy = createPolicyBuilder()
      .role('admin')
      .resource('post', ['read'])
      .permit('admin', 'post', ['read'])
      .build();
    expect(policy.__brand).toBe('authkit/policy');
    expect(policy.spec.roles.admin).toBeDefined();
  });

  it('should set version', () => {
    const policy = createPolicyBuilder()
      .version('v2')
      .role('admin')
      .resource('post', ['read'])
      .permit('admin', 'post', ['read'])
      .build();
    expect(policy.spec.version).toBe('v2');
  });

  it('should support role inheritance and crossTenant flag', () => {
    const policy = createPolicyBuilder()
      .role('member')
      .role('admin', { extends: ['member'], description: 'admin role' })
      .role('superAdmin', { extends: ['admin'], crossTenant: true })
      .resource('doc', ['read'])
      .permit('member', 'doc', ['read'])
      .build();
    expect(policy.spec.roles.admin?.extends).toEqual(['member']);
    expect(policy.spec.roles.superAdmin?.crossTenant).toBe(true);
    expect(policy.spec.roles.admin?.description).toBe('admin role');
  });

  it('should attach resource description when provided', () => {
    const policy = createPolicyBuilder()
      .role('m')
      .resource('doc', ['read'], 'docs description')
      .permit('m', 'doc', ['read'])
      .build();
    expect(policy.spec.resources.doc?.description).toBe('docs description');
  });

  it('should register tagged conditions', () => {
    const cond = defineCondition(() => true);
    const policy = createPolicyBuilder()
      .role('m')
      .resource('doc', ['read'])
      .condition('always', cond)
      .permit('m', 'doc', { read: { when: 'always' } })
      .build();
    expect(policy.spec.conditions?.always).toBe(cond);
  });

  it('should produce an enforceable policy end-to-end', async () => {
    const policy = createPolicyBuilder()
      .role('m')
      .resource('doc', ['read'])
      .permit('m', 'doc', ['read'])
      .build();
    const enforcer = createEnforcer(policy);
    const subject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
    await expect(
      enforcer.check({ subject, resource: 'doc', action: 'read' }),
    ).resolves.toBe(true);
  });

  it('should throw when calling permit with unknown role at build time', () => {
    expect(() =>
      createPolicyBuilder()
        .resource('doc', ['read'])
        .permit('ghost', 'doc', ['read'])
        .build(),
    ).toThrow();
  });

  it('should throw when calling permit on undeclared action', () => {
    expect(() =>
      createPolicyBuilder()
        .role('m')
        .resource('doc', ['read'])
        .permit('m', 'doc', ['burn'])
        .build(),
    ).toThrow();
  });

  it('should preserve permit ordering when called multiple times for same role', () => {
    const policy = createPolicyBuilder()
      .role('m')
      .resource('doc', ['read', 'update'])
      .permit('m', 'doc', ['read'])
      .permit('m', 'doc', ['update'])
      .build();
    expect(policy.spec.permissions.m?.doc).toEqual(['update']);
  });
});
