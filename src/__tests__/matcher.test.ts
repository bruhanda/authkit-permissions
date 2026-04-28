import { describe, expect, it } from 'vitest';
import { actionMatches } from '../core/matcher.js';

describe('actionMatches', () => {
  it('should match identical literals', () => {
    expect(actionMatches('read', 'read')).toBe(true);
  });

  it('should match the wildcard against any action', () => {
    expect(actionMatches('*', 'read')).toBe(true);
    expect(actionMatches('*', 'delete')).toBe(true);
    expect(actionMatches('*', '')).toBe(true);
  });

  it('should not match different literals', () => {
    expect(actionMatches('read', 'update')).toBe(false);
    expect(actionMatches('read', 'READ')).toBe(false);
  });

  it('should not match wildcard requested against literal declared', () => {
    expect(actionMatches('read', '*')).toBe(false);
  });
});
