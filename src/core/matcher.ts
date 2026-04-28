/**
 * Match an action key from a permission entry against a requested action.
 *
 * The library uses simple literal matching plus a single `'*'` wildcard.
 * No regex, no glob — keeps the hot path branch-free and predictable.
 *
 * @param declared - action key from the compiled rule (or `'*'`).
 * @param requested - action requested at the call site.
 * @returns `true` when the rule applies.
 *
 * @example
 *   actionMatches('*', 'read')      // true
 *   actionMatches('read', 'read')   // true
 *   actionMatches('read', 'update') // false
 */
export function actionMatches(declared: string, requested: string): boolean {
  return declared === '*' || declared === requested;
}
