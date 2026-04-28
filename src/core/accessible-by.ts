import type { DeclarativeCondition } from '../types/condition.js';
import type {
  DefaultInstances,
  InferActions,
  InferResources,
  ResourceInstanceMap,
} from '../types/inference.js';
import type { NormalizedRule, PolicyDefinition } from '../types/policy.js';
import type { Subject } from '../types/subject.js';
import { resolveDeclarativeValue } from './condition.js';
import type { Ability } from './ability.js';

/**
 * Filter AST returned by `accessibleBy()`. ORM adapters under
 * `@authkit/permissions/orm/{prisma,drizzle,mongoose}` translate this to
 * the native `where` clause for the host.
 */
export type AccessibleByFilter =
  | { readonly kind: 'all' }
  | { readonly kind: 'none' }
  | { readonly kind: 'and'; readonly filters: readonly AccessibleByFilter[] }
  | { readonly kind: 'or'; readonly filters: readonly AccessibleByFilter[] }
  | { readonly kind: 'eq'; readonly field: string; readonly value: unknown }
  | { readonly kind: 'in'; readonly field: string; readonly values: readonly unknown[] };

/**
 * Build a filter AST that selects every row the subject is allowed to
 * access for `(resource, action?)`.
 *
 * Behaviour:
 *   - Built-in tenant guard always emits `{ kind: 'eq', field: 'tenantId', value: subject.tenantId }`,
 *     unless `subject.crossTenant === true` and the policy's
 *     `allowCrossTenant === true` (then emits `{ kind: 'all' }` for tenant).
 *   - Declarative conditions (`eq` / `inList`) compile to their native
 *     filter AST nodes.
 *   - Opaque function conditions return `{ kind: 'all' }` and the caller
 *     must post-filter row by row. The result includes `warning: 'opaque_condition'`
 *     on the surrounding wrapper if present.
 *   - Empty intersection (deny-overrides + no allow rule) → `{ kind: 'none' }`,
 *     adapters translate to a falsy SQL predicate / `_id: { $in: [] }`.
 *
 * @param ability A subject-bound `Ability` (use `permissions.abilityFor(subject)`).
 * @param args.resource The resource key.
 * @param args.action Optional action — when omitted, "any allowed action" semantics apply.
 *
 * @returns A normalized filter AST.
 *
 * @throws Never throws.
 *
 * @example
 * ```ts
 * const filter = accessibleBy(ability, { resource: 'post', action: 'read' });
 * const where = toPrisma(filter);
 * const rows = await prisma.post.findMany({ where });
 * ```
 */
export function accessibleBy<
  TPolicy extends PolicyDefinition,
  R extends InferResources<TPolicy>,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(
  ability: Ability<TPolicy, TInstances>,
  args: { resource: R; action?: InferActions<TPolicy, R> },
): AccessibleByFilter {
  const subject = ability.subject as Subject;
  const compiled = ability.compiled;
  const options = compiled.options ?? {};
  const strictTenant = options.strictTenant !== false;
  const allowCrossTenant = options.allowCrossTenant === true;

  if (strictTenant && subject.crossTenant === true && !allowCrossTenant) {
    return { kind: 'none' };
  }

  const effective = compiled.roleGraph.expand(subject.roles);
  if (effective.length === 0) return { kind: 'none' };

  const allowFilters: AccessibleByFilter[] = [];
  let hasUnconditionalAllow = false;
  let hasDeny = false;

  for (const rule of compiled.rules) {
    if (!ruleMatchesResourceAction(rule, args.resource as string, args.action as string | undefined)) {
      continue;
    }
    if (!hasOverlap(effective, rule.roles)) continue;

    if (rule.effect === 'deny') {
      hasDeny = true;
      continue;
    }

    // 'allow'
    if (!rule.condition) {
      hasUnconditionalAllow = true;
      continue;
    }
    if (typeof rule.condition === 'function') {
      // Opaque function — caller must post-filter.
      return { kind: 'all' };
    }
    allowFilters.push(declarativeToFilter(rule.condition, subject));
  }

  if (!hasUnconditionalAllow && allowFilters.length === 0) {
    // Deny-with-no-allow OR pure-no-match → empty result.
    void hasDeny;
    return { kind: 'none' };
  }

  // Build allow side: union of every applicable allow.
  const allowSide: AccessibleByFilter = hasUnconditionalAllow
    ? { kind: 'all' }
    : allowFilters.length === 1
      ? (allowFilters[0] as AccessibleByFilter)
      : { kind: 'or', filters: allowFilters };

  // Tenant guard: AND with `tenantId === subject.tenantId` unless cross-tenant.
  const tenantClause = buildTenantClause(subject, options);
  if (!tenantClause) return allowSide;
  if (allowSide.kind === 'all') return tenantClause;
  return { kind: 'and', filters: [tenantClause, allowSide] };
}

function buildTenantClause(
  subject: Subject,
  options: PolicyDefinition['options'],
): AccessibleByFilter | null {
  if (options?.strictTenant === false) return null;
  if (subject.crossTenant === true && options?.allowCrossTenant === true) return null;
  if (!subject.tenantId) return { kind: 'none' };
  return { kind: 'eq', field: 'tenantId', value: subject.tenantId };
}

function ruleMatchesResourceAction(
  rule: NormalizedRule,
  resource: string,
  action: string | undefined,
): boolean {
  if (rule.resources !== '*' && !rule.resources.includes(resource)) return false;
  if (action === undefined) return true;
  if (rule.actions !== '*' && !rule.actions.includes(action)) return false;
  return true;
}

function hasOverlap(a: readonly string[], b: readonly string[]): boolean {
  const set = new Set(b);
  for (const v of a) if (set.has(v)) return true;
  return false;
}

function declarativeToFilter(
  cond: DeclarativeCondition,
  subject: Subject,
): AccessibleByFilter {
  if (cond.kind === 'declarative-eq') {
    return { kind: 'eq', field: cond.field, value: resolveDeclarativeValue(cond, subject) };
  }
  const values = resolveDeclarativeValue(cond, subject) as readonly unknown[];
  return { kind: 'in', field: cond.field, values };
}

/**
 * Build a declarative `eq` condition that the ORM adapters can lower to
 * native SQL/Mongo. Use inside a rule's `condition` field instead of an
 * opaque arrow function whenever you need row-level filtering at the DB.
 *
 * @param field The field name on the resource row.
 * @param value Either a literal or a `(subject) => value` resolver.
 *
 * @returns A `DeclarativeCondition` that compiles to `field = value`.
 *
 * @example
 * ```ts
 * { role: 'member', resource: 'post', action: 'read',
 *   condition: eq('authorId', (s) => s.id) }
 * ```
 */
export const eq = (
  field: string,
  value: unknown | ((s: Subject) => unknown),
): DeclarativeCondition => ({ kind: 'declarative-eq', field, value });

/**
 * Build a declarative `in` condition.
 *
 * @param field The field name on the resource row.
 * @param values Either a literal array or a `(subject) => values` resolver.
 *
 * @returns A `DeclarativeCondition` that compiles to `field IN (values)`.
 *
 * @example
 * ```ts
 * { role: 'member', resource: 'project', action: 'read',
 *   condition: inList('memberIds', (s) => s.id) }
 * ```
 */
export const inList = (
  field: string,
  values: readonly unknown[] | ((s: Subject) => readonly unknown[]),
): DeclarativeCondition => ({ kind: 'declarative-in', field, values });
