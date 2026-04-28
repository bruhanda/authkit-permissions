import { describe, expect, it } from 'vitest';
import {
  PermissionsGuard,
  REQUIRES_METADATA_KEY,
  Requires,
} from '../adapters/nestjs/index.js';
import {
  PERMISSIONS_ENFORCER,
  PermissionsModule,
} from '../adapters/nestjs/module.js';
import { createEnforcer } from '../core/enforcer.js';
import { definePolicy } from '../core/policy.js';
import { createSubject } from '../core/subject.js';
import { PermissionError } from '../errors/base.js';
import type { NestExecutionContextLike, ReflectorLike } from '../adapters/nestjs/index.js';

const policy = definePolicy({
  roles: { m: {} },
  resources: { d: { actions: ['read'] } },
  permissions: { m: { d: ['read'] } },
});

const enforcer = createEnforcer(policy);
const allowedSubject = createSubject({ id: 'u', roles: ['m'] as const, tenantId: 't1' });
const deniedSubject = createSubject({ id: 'u', roles: [] as const, tenantId: 't1' });

const buildContext = (request: object): NestExecutionContextLike => ({
  switchToHttp: () => ({ getRequest: () => request as { user?: unknown } & Record<string, unknown> }),
  getHandler: () => ({}),
});

const buildReflector = <T>(value: T | undefined): ReflectorLike => ({
  get: () => value as T | undefined,
});

describe('Requires', () => {
  it('should attach metadata via Reflect.defineMetadata when available', () => {
    const calls: Array<[string, unknown, unknown, unknown?]> = [];
    const reflectAny = Reflect as unknown as Record<string, unknown>;
    const had = 'defineMetadata' in reflectAny;
    const previous = reflectAny.defineMetadata;
    reflectAny.defineMetadata = (
      k: string,
      v: unknown,
      t: object,
      p?: unknown,
    ): void => {
      calls.push([k, v, t, p]);
    };
    try {
      const decorator = Requires({ resource: 'd', action: 'read' } as never);
      const handler = function noop(): void {};
      decorator({}, 'method', { value: handler });
      expect(calls.length).toBe(1);
      expect(calls[0]?.[0]).toBe(REQUIRES_METADATA_KEY);
      expect(calls[0]?.[1]).toEqual({ resource: 'd', action: 'read' });
    } finally {
      if (had) reflectAny.defineMetadata = previous;
      else delete reflectAny.defineMetadata;
    }
  });

  it('should fall back to direct metadata stash when Reflect.defineMetadata is absent', () => {
    const reflectAny = Reflect as unknown as Record<string, unknown>;
    const had = 'defineMetadata' in reflectAny;
    const previous = reflectAny.defineMetadata;
    delete reflectAny.defineMetadata;
    try {
      const decorator = Requires({ resource: 'd', action: 'read' } as never);
      const handler = function noop(): void {};
      decorator({}, 'method', { value: handler });
      const stash = `__authkit_meta_${REQUIRES_METADATA_KEY}`;
      expect((handler as Record<string, unknown>)[stash]).toEqual({
        resource: 'd',
        action: 'read',
      });
    } finally {
      if (had) reflectAny.defineMetadata = previous;
    }
  });

  it('should attach to target+propertyKey when descriptor.value is not a function', () => {
    const reflectAny = Reflect as unknown as Record<string, unknown>;
    const had = 'defineMetadata' in reflectAny;
    const previous = reflectAny.defineMetadata;
    delete reflectAny.defineMetadata;
    try {
      const decorator = Requires({ resource: 'd', action: 'read' } as never);
      const target = {} as Record<string, unknown>;
      decorator(target, 'method', {});
      const stash = `__authkit_meta_${REQUIRES_METADATA_KEY}`;
      expect(target[stash]).toEqual({ resource: 'd', action: 'read' });
    } finally {
      if (had) reflectAny.defineMetadata = previous;
    }
  });
});

describe('PermissionsGuard', () => {
  it('should allow when no requirement metadata is present', async () => {
    const guard = new PermissionsGuard(
      buildReflector(undefined),
      enforcer,
      () => allowedSubject,
    );
    await expect(guard.canActivate(buildContext({}))).resolves.toBe(true);
  });

  it('should allow when requirement is satisfied', async () => {
    const guard = new PermissionsGuard(
      buildReflector({ resource: 'd', action: 'read' }),
      enforcer,
      () => allowedSubject,
    );
    await expect(guard.canActivate(buildContext({}))).resolves.toBe(true);
  });

  it('should throw FORBIDDEN when denied', async () => {
    const guard = new PermissionsGuard(
      buildReflector({ resource: 'd', action: 'read' }),
      enforcer,
      () => deniedSubject,
    );
    await expect(guard.canActivate(buildContext({}))).rejects.toBeInstanceOf(PermissionError);
  });

  it('should support async getSubject', async () => {
    const guard = new PermissionsGuard(
      buildReflector({ resource: 'd', action: 'read' }),
      enforcer,
      async () => allowedSubject,
    );
    await expect(guard.canActivate(buildContext({}))).resolves.toBe(true);
  });
});

describe('PermissionsModule', () => {
  it('should produce a global dynamic module wrapping the enforcer', () => {
    const mod = PermissionsModule.forRoot(enforcer);
    expect(mod.module).toBe(PermissionsModule);
    expect(mod.global).toBe(true);
    expect(mod.exports).toEqual([PERMISSIONS_ENFORCER]);
    expect(mod.providers[0]?.provide).toBe(PERMISSIONS_ENFORCER);
    expect(mod.providers[0]?.useValue).toBe(enforcer);
  });
});
