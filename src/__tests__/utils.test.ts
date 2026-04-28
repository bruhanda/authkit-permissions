import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest';
import { isDev } from '../utils/env.js';
import { invariant } from '../utils/invariant.js';
import { isRecord } from '../utils/is-record.js';
import { PermissionError } from '../errors/base.js';
import { ERROR_CODES } from '../errors/codes.js';

describe('isRecord', () => {
  it('should return true when value is a plain object', () => {
    expect(isRecord({})).toBe(true);
    expect(isRecord({ a: 1 })).toBe(true);
    expect(isRecord(Object.create(null))).toBe(true);
  });

  it('should return false when value is null', () => {
    expect(isRecord(null)).toBe(false);
  });

  it('should return false when value is an array', () => {
    expect(isRecord([])).toBe(false);
    expect(isRecord([1, 2, 3])).toBe(false);
  });

  it('should return false when value is a primitive', () => {
    expect(isRecord(1)).toBe(false);
    expect(isRecord('string')).toBe(false);
    expect(isRecord(true)).toBe(false);
    expect(isRecord(undefined)).toBe(false);
    expect(isRecord(Symbol('x'))).toBe(false);
  });

  it('should narrow type when used as a guard', () => {
    const value: unknown = { foo: 'bar' };
    if (isRecord(value)) {
      expectTypeOf(value).toMatchTypeOf<Record<string, unknown>>();
    }
  });
});

describe('isDev', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it('should return true when NODE_ENV is not production', () => {
    process.env.NODE_ENV = 'development';
    expect(isDev()).toBe(true);
  });

  it('should return false when NODE_ENV is production', () => {
    process.env.NODE_ENV = 'production';
    expect(isDev()).toBe(false);
  });

  it('should return true when NODE_ENV is test', () => {
    process.env.NODE_ENV = 'test';
    expect(isDev()).toBe(true);
  });

  it('should return true when NODE_ENV is undefined', () => {
    delete process.env.NODE_ENV;
    expect(isDev()).toBe(true);
  });
});

describe('invariant', () => {
  it('should not throw when condition is truthy', () => {
    expect(() => invariant(true, ERROR_CODES.INVALID_POLICY, 'ok')).not.toThrow();
    expect(() => invariant(1, ERROR_CODES.INVALID_POLICY, 'ok')).not.toThrow();
    expect(() => invariant('value', ERROR_CODES.INVALID_POLICY, 'ok')).not.toThrow();
    expect(() => invariant({}, ERROR_CODES.INVALID_POLICY, 'ok')).not.toThrow();
  });

  it('should throw PermissionError when condition is falsy', () => {
    expect(() => invariant(false, ERROR_CODES.INVALID_POLICY, 'bad')).toThrow(PermissionError);
    expect(() => invariant(0, ERROR_CODES.INVALID_POLICY, 'bad')).toThrow(PermissionError);
    expect(() => invariant(null, ERROR_CODES.INVALID_POLICY, 'bad')).toThrow(PermissionError);
    expect(() => invariant(undefined, ERROR_CODES.INVALID_POLICY, 'bad')).toThrow(PermissionError);
    expect(() => invariant('', ERROR_CODES.INVALID_POLICY, 'bad')).toThrow(PermissionError);
  });

  it('should attach context to the thrown error when supplied', () => {
    try {
      invariant(false, ERROR_CODES.TENANT_REQUIRED, 'tenant missing', { subjectId: 'u1' });
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PermissionError);
      const pe = err as PermissionError;
      expect(pe.code).toBe(ERROR_CODES.TENANT_REQUIRED);
      expect(pe.message).toBe('tenant missing');
      expect(pe.context).toEqual({ subjectId: 'u1' });
    }
  });

  it('should narrow types when used as an assertion', () => {
    const value: string | undefined = 'present';
    invariant(value !== undefined, ERROR_CODES.INVALID_POLICY, 'expected');
    expectTypeOf(value).toEqualTypeOf<string | undefined>();
  });
});
