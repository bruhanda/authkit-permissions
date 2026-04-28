import { describe, expect, it } from 'vitest';
import { LRU } from '../core/memo.js';

describe('LRU', () => {
  it('should return undefined for missing keys', () => {
    const cache = new LRU<number>(3);
    expect(cache.get('missing')).toBeUndefined();
  });

  it('should return the cached value on hit', () => {
    const cache = new LRU<string>(2);
    cache.set('a', 'A');
    expect(cache.get('a')).toBe('A');
  });

  it('should evict the least-recently-used entry when capacity is reached', () => {
    const cache = new LRU<number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
  });

  it('should refresh recency on get', () => {
    const cache = new LRU<number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.get('a')).toBe(1);
    cache.set('c', 3);
    expect(cache.get('a')).toBe(1);
    expect(cache.get('b')).toBeUndefined();
  });

  it('should overwrite existing keys without growing the size beyond capacity', () => {
    const cache = new LRU<number>(2);
    cache.set('a', 1);
    cache.set('a', 10);
    cache.set('b', 2);
    expect(cache.get('a')).toBe(10);
    expect(cache.get('b')).toBe(2);
  });

  it('should refresh recency when overwriting', () => {
    const cache = new LRU<number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('a', 11);
    cache.set('c', 3);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe(11);
    expect(cache.get('c')).toBe(3);
  });

  it('should throw RangeError when capacity is below 1', () => {
    expect(() => new LRU<number>(0)).toThrow(RangeError);
    expect(() => new LRU<number>(-1)).toThrow(RangeError);
  });

  it('should accept capacity of 1', () => {
    const cache = new LRU<number>(1);
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
  });
});
