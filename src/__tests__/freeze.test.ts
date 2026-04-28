import { describe, expect, it } from 'vitest';
import { deepFreeze } from '../core/freeze.js';

describe('deepFreeze', () => {
  it('should pass primitives through', () => {
    expect(deepFreeze(42)).toBe(42);
    expect(deepFreeze('a')).toBe('a');
    expect(deepFreeze(true)).toBe(true);
    expect(deepFreeze(null)).toBeNull();
    expect(deepFreeze(undefined)).toBeUndefined();
  });

  it('should freeze a flat object', () => {
    const obj = deepFreeze({ a: 1, b: 2 });
    expect(Object.isFrozen(obj)).toBe(true);
  });

  it('should freeze nested objects recursively', () => {
    const obj = deepFreeze({ a: { b: { c: 1 } } });
    expect(Object.isFrozen(obj)).toBe(true);
    expect(Object.isFrozen(obj.a)).toBe(true);
    expect(Object.isFrozen(obj.a.b)).toBe(true);
  });

  it('should freeze arrays and their elements', () => {
    const arr = deepFreeze([{ a: 1 }, { b: 2 }]);
    expect(Object.isFrozen(arr)).toBe(true);
    expect(Object.isFrozen(arr[0])).toBe(true);
    expect(Object.isFrozen(arr[1])).toBe(true);
  });

  it('should not re-walk an already-frozen subtree (cycle / efficiency guard)', () => {
    const inner = Object.freeze({ x: 1 });
    const outer = { inner };
    deepFreeze(outer);
    expect(Object.isFrozen(outer)).toBe(true);
  });

  it('should return the same reference', () => {
    const obj = { a: 1 };
    expect(deepFreeze(obj)).toBe(obj);
  });

  it('should throw on mutation in strict mode after freezing', () => {
    'use strict';
    const obj = deepFreeze({ a: 1 });
    expect(() => {
      (obj as { a: number }).a = 2;
    }).toThrow();
  });
});
