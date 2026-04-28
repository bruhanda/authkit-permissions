/**
 * Per-subject memoization for `Ability.can()` decisions.
 *
 * The cache lives in a `WeakMap<Subject, Map<string, Decision>>` so it is
 * automatically reclaimed when the subject is GC'd — typical request-scoped
 * objects therefore never need explicit cleanup. We only memoize `(resource,
 * action)` lookups; calls that include a `target` or a `context` skip the
 * cache because conditions can return different verdicts for different
 * inputs.
 */

import type { Decision } from '../types/decision.js';

export type DecisionCache = Map<string, Decision>;

const stores = new WeakMap<object, DecisionCache>();

/**
 * Get-or-create the per-subject cache for a given subject identity.
 *
 * @param subjectKey Any subject-derived object identity. The `Subject` itself
 *                   is the most common; ability instances also work.
 */
export const cacheFor = (subjectKey: object): DecisionCache => {
  let cache = stores.get(subjectKey);
  if (!cache) {
    cache = new Map();
    stores.set(subjectKey, cache);
  }
  return cache;
};

/** Build a stable cache key from `(resource, action)`. */
export const cacheKey = (resource: string, action: string): string =>
  `${resource}|${action}`;
