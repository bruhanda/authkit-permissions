import { describe, expect, expectTypeOf, it } from 'vitest';
import { PermissionError, ERROR_CODES, type ErrorCode } from '../errors/index.js';

describe('PermissionError', () => {
  it('should be instance of Error', () => {
    const err = new PermissionError(ERROR_CODES.FORBIDDEN, 'denied');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(PermissionError);
  });

  it('should set name to PermissionError', () => {
    const err = new PermissionError(ERROR_CODES.FORBIDDEN, 'denied');
    expect(err.name).toBe('PermissionError');
  });

  it('should expose the code discriminator', () => {
    const err = new PermissionError(ERROR_CODES.UNKNOWN_ROLE, 'no role', { role: 'guest' });
    expect(err.code).toBe('UNKNOWN_ROLE');
    expect(err.message).toBe('no role');
  });

  it('should freeze the supplied context', () => {
    const err = new PermissionError(ERROR_CODES.UNKNOWN_ROLE, 'no role', { role: 'guest' });
    expect(err.context).toEqual({ role: 'guest' });
    expect(Object.isFrozen(err.context)).toBe(true);
    expect(() => {
      (err.context as Record<string, unknown>).role = 'mutated';
    }).toThrow();
  });

  it('should leave context undefined when not supplied', () => {
    const err = new PermissionError(ERROR_CODES.FORBIDDEN, 'denied');
    expect(err.context).toBeUndefined();
  });

  it('should attach cause when provided', () => {
    const cause = new Error('underlying');
    const err = new PermissionError(ERROR_CODES.CONDITION_THREW, 'wrap', undefined, cause);
    expect(err.cause).toBe(cause);
  });

  it('should not attach cause when undefined', () => {
    const err = new PermissionError(ERROR_CODES.FORBIDDEN, 'no cause');
    expect(err.cause).toBeUndefined();
  });
});

describe('ERROR_CODES', () => {
  it('should be frozen', () => {
    expect(Object.isFrozen(ERROR_CODES)).toBe(true);
  });

  it('should expose every documented code', () => {
    expect(ERROR_CODES.INVALID_POLICY).toBe('INVALID_POLICY');
    expect(ERROR_CODES.ROLE_CYCLE).toBe('ROLE_CYCLE');
    expect(ERROR_CODES.UNKNOWN_ROLE).toBe('UNKNOWN_ROLE');
    expect(ERROR_CODES.UNKNOWN_RESOURCE).toBe('UNKNOWN_RESOURCE');
    expect(ERROR_CODES.UNKNOWN_ACTION).toBe('UNKNOWN_ACTION');
    expect(ERROR_CODES.UNKNOWN_CONDITION).toBe('UNKNOWN_CONDITION');
    expect(ERROR_CODES.TENANT_REQUIRED).toBe('TENANT_REQUIRED');
    expect(ERROR_CODES.TENANT_MISMATCH).toBe('TENANT_MISMATCH');
    expect(ERROR_CODES.CONDITION_THREW).toBe('CONDITION_THREW');
    expect(ERROR_CODES.ASYNC_CONDITION_IN_SYNC_PATH).toBe('ASYNC_CONDITION_IN_SYNC_PATH');
    expect(ERROR_CODES.AUDIT_FAILED).toBe('AUDIT_FAILED');
    expect(ERROR_CODES.FORBIDDEN).toBe('FORBIDDEN');
  });

  it('should derive ErrorCode union from values', () => {
    expectTypeOf<ErrorCode>().toEqualTypeOf<
      | 'INVALID_POLICY'
      | 'ROLE_CYCLE'
      | 'UNKNOWN_ROLE'
      | 'UNKNOWN_RESOURCE'
      | 'UNKNOWN_ACTION'
      | 'UNKNOWN_CONDITION'
      | 'TENANT_REQUIRED'
      | 'TENANT_MISMATCH'
      | 'CONDITION_THREW'
      | 'ASYNC_CONDITION_IN_SYNC_PATH'
      | 'AUDIT_FAILED'
      | 'FORBIDDEN'
    >();
  });
});
