import type {
  ConditionArgs,
  ConditionEntry,
  TaggedAsyncCondition,
  TaggedSyncCondition,
} from '../types/condition.js';
import type { ResourceDataMap } from '../types/context.js';
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
 * Two call shapes:
 *
 * 1. With a `resourceType` literal — narrows `args.resource` inside the
 *    body via `ResourceDataMap[R]` (plan §4.4). The literal is for typing
 *    only; runtime dispatch is by name as declared in the policy.
 * 2. Without a literal — `args.resource` is the wide
 *    `Record<string, unknown> | undefined`.
 *
 * @example
 *   declare module '@authkit/permissions' {
 *     interface ResourceDataMap {
 *       document: { ownerId: string };
 *     }
 *   }
 *
 *   const isOwner = defineCondition(
 *     'document',
 *     ({ subject, resource }) => resource?.ownerId === subject.id,
 *     { filter: (subject) => ({ kind: 'eq', field: 'ownerId', value: subject.id }) },
 *   );
 */
export function defineCondition<R extends keyof ResourceDataMap & string>(
  resourceType: R,
  fn: (args: ConditionArgs<R>) => boolean,
  hint?: ConditionFilterHint,
): TaggedSyncCondition<ConditionArgs<R>>;
export function defineCondition<TArgs = ConditionArgs>(
  fn: (args: TArgs) => boolean,
  hint?: ConditionFilterHint,
): TaggedSyncCondition<TArgs>;
// biome-ignore lint/suspicious/noExplicitAny: implementation-only signature
export function defineCondition(
  arg1: string | ((args: any) => boolean),
  // biome-ignore lint/suspicious/noExplicitAny: implementation-only signature
  arg2?: ((args: any) => boolean) | ConditionFilterHint,
  arg3?: ConditionFilterHint,
): TaggedSyncCondition {
  // biome-ignore lint/suspicious/noExplicitAny: implementation-only signature
  const fn = (typeof arg1 === 'function' ? arg1 : arg2) as (args: any) => boolean;
  const hint = (typeof arg1 === 'function' ? arg2 : arg3) as ConditionFilterHint | undefined;
  Object.defineProperty(fn, MODE_KEY, {
    value: 'sync',
    enumerable: false,
    configurable: false,
    writable: false,
  });
  if (hint !== undefined) attachFilter(fn, hint.filter);
  return fn as unknown as TaggedSyncCondition;
}

/**
 * Tag an async predicate so the engine knows to dispatch via `await`.
 *
 * Async conditions can also carry a filter hint — `accessibleBy()` is
 * synchronous and the hint itself is sync, so this works regardless of
 * the condition's runtime cost. Accepts the same `(resourceType, fn)`
 * narrowing shape as `defineCondition`.
 *
 * @example
 *   const isCollaborator = defineAsyncCondition(
 *     'document',
 *     async ({ subject, resource }) => repo.isCollaborator(subject.id, resource?.id),
 *   );
 */
export function defineAsyncCondition<R extends keyof ResourceDataMap & string>(
  resourceType: R,
  fn: (args: ConditionArgs<R>) => Promise<boolean>,
  hint?: ConditionFilterHint,
): TaggedAsyncCondition<ConditionArgs<R>>;
export function defineAsyncCondition<TArgs = ConditionArgs>(
  fn: (args: TArgs) => Promise<boolean>,
  hint?: ConditionFilterHint,
): TaggedAsyncCondition<TArgs>;
// biome-ignore lint/suspicious/noExplicitAny: implementation-only signature
export function defineAsyncCondition(
  arg1: string | ((args: any) => Promise<boolean>),
  // biome-ignore lint/suspicious/noExplicitAny: implementation-only signature
  arg2?: ((args: any) => Promise<boolean>) | ConditionFilterHint,
  arg3?: ConditionFilterHint,
): TaggedAsyncCondition {
  // biome-ignore lint/suspicious/noExplicitAny: implementation-only signature
  const fn = (typeof arg1 === 'function' ? arg1 : arg2) as (args: any) => Promise<boolean>;
  const hint = (typeof arg1 === 'function' ? arg2 : arg3) as ConditionFilterHint | undefined;
  Object.defineProperty(fn, MODE_KEY, {
    value: 'async',
    enumerable: false,
    configurable: false,
    writable: false,
  });
  if (hint !== undefined) attachFilter(fn, hint.filter);
  return fn as unknown as TaggedAsyncCondition;
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
