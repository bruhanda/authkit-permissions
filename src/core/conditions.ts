import type {
  ConditionArgs,
  ConditionEntry,
  TaggedAsyncCondition,
  TaggedSyncCondition,
} from '../types/condition.js';
import type { FilterAst } from '../types/filter.js';
import type { Subject } from '../types/subject.js';

const MODE_KEY = '__authkitMode';
const FILTER_KEY = '__authkitFilter';

/**
 * Optional filter hint attached to a condition.
 *
 * When provided, `accessibleBy()` lowers the condition into a `FilterAst`
 * suitable for SQL/Mongo `where` clauses (plan §2.5). When absent, the
 * condition becomes an `opaque` node and the ORM translator treats it as
 * "match all + post-fetch check".
 */
export interface ConditionFilterHint {
  readonly filter: (subject: Subject) => FilterAst;
}

/**
 * Tag a sync predicate so it runs on the `enforcer.checkSync` fast-path.
 *
 * Optionally attach a filter hint that `accessibleBy()` lowers into a
 * SQL/Mongo `where` clause for row-level filtering.
 *
 * @param fn - sync predicate.
 * @param hint - optional `{ filter }` mapping the condition to a `FilterAst`.
 * @returns `fn` itself, with the `__authkitMode: 'sync'` brand attached
 *   (and the filter hint when supplied).
 *
 * @example
 *   const isOwner = defineCondition(
 *     ({ subject, resource }) => resource?.ownerId === subject.id,
 *     { filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }) },
 *   );
 */
export function defineCondition<TArgs = ConditionArgs>(
  fn: (args: TArgs) => boolean,
  hint?: ConditionFilterHint,
): TaggedSyncCondition<TArgs> {
  Object.defineProperty(fn, MODE_KEY, {
    value: 'sync',
    enumerable: false,
    configurable: false,
    writable: false,
  });
  if (hint !== undefined) attachFilter(fn, hint.filter);
  return fn as unknown as TaggedSyncCondition<TArgs>;
}

/**
 * Tag an async predicate so the engine knows to dispatch via `await`.
 *
 * Async conditions can also carry a filter hint — `accessibleBy()` is
 * synchronous and the hint itself is sync, so this works regardless of
 * the condition's runtime cost.
 *
 * @param fn - async predicate.
 * @param hint - optional `{ filter }` mapping the condition to a `FilterAst`.
 * @returns `fn` itself, with the `__authkitMode: 'async'` brand attached.
 *
 * @example
 *   const isCollaborator = defineAsyncCondition(
 *     async ({ subject, resource }) => repo.isCollaborator(subject.id, resource?.id),
 *   );
 */
export function defineAsyncCondition<TArgs = ConditionArgs>(
  fn: (args: TArgs) => Promise<boolean>,
  hint?: ConditionFilterHint,
): TaggedAsyncCondition<TArgs> {
  Object.defineProperty(fn, MODE_KEY, {
    value: 'async',
    enumerable: false,
    configurable: false,
    writable: false,
  });
  if (hint !== undefined) attachFilter(fn, hint.filter);
  return fn as unknown as TaggedAsyncCondition<TArgs>;
}

/** Returns `true` when the entry was registered via `defineCondition`. */
export function isSyncCondition(entry: ConditionEntry): boolean {
  return (entry as { __authkitMode?: string }).__authkitMode === 'sync';
}

/** Returns `true` when the entry was registered via `defineAsyncCondition`. */
export function isAsyncCondition(entry: ConditionEntry): boolean {
  return (entry as { __authkitMode?: string }).__authkitMode === 'async';
}

/** Get the attached filter hint for a condition, if any. */
export function getConditionFilter(
  entry: ConditionEntry,
): ((subject: Subject) => FilterAst) | undefined {
  return (entry as { __authkitFilter?: (subject: Subject) => FilterAst }).__authkitFilter;
}

function attachFilter(fn: object, filter: (subject: Subject) => FilterAst): void {
  Object.defineProperty(fn, FILTER_KEY, {
    value: filter,
    enumerable: false,
    configurable: false,
    writable: false,
  });
}
