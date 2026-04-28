import type {
  DefaultInstances,
  ResourceInstanceMap,
} from '../types/inference.js';
import type {
  PolicyDefinition,
  RoleDefinition,
  ResourceDefinition,
  RuleLike,
} from '../types/policy.js';
import type { Permissions } from './permissions.js';

/**
 * JSON-serialisable shape of a policy. Conditions are dropped — they are
 * server-side only — and a `__hasConditions` flag is set so consumers can
 * decide whether to round-trip through the wire safely.
 */
export interface SerializedPolicy {
  readonly version: 1;
  readonly options: PolicyDefinition['options'];
  readonly id?: string;
  readonly roles: Readonly<Record<string, RoleDefinition>>;
  readonly resources: Readonly<Record<string, ResourceDefinition>>;
  readonly rules: ReadonlyArray<SerializedRule>;
  /** `true` when at least one rule had a condition (which has been dropped). */
  readonly __hasConditions: boolean;
}

export interface SerializedRule extends Omit<RuleLike, 'condition'> {
  /** Always `undefined` — kept in the type for shape parity with the live rule. */
  readonly condition?: undefined;
}

/**
 * Serialize a `Permissions` instance to a JSON-friendly object.
 *
 * Conditions are dropped from the output (they are non-serializable
 * functions). The output is suitable for snapshotting policy revisions
 * into a SOC2 audit trail.
 *
 * @param permissions A `Permissions` instance produced by `definePolicy()`.
 *
 * @returns A plain, structured-clone-safe object describing the policy.
 *
 * @throws Never throws.
 *
 * @example
 * ```ts
 * import { definePolicy, serialize } from '@authkit/permissions';
 *
 * const p = definePolicy({ ... });
 * const snapshot = serialize(p);
 * fs.writeFileSync('policy.json', JSON.stringify(snapshot, null, 2));
 * ```
 */
export function serialize<
  TPolicy extends PolicyDefinition,
  TInstances extends ResourceInstanceMap<TPolicy> = DefaultInstances<TPolicy>,
>(permissions: Permissions<TPolicy, TInstances>): SerializedPolicy {
  const policy = permissions.policy as PolicyDefinition;
  let hasConditions = false;
  const rules: SerializedRule[] = policy.rules.map((rule) => {
    if (rule.condition !== undefined) hasConditions = true;
    const out: { -readonly [K in keyof SerializedRule]: SerializedRule[K] } = {
      role: rule.role,
      resource: rule.resource,
      action: rule.action,
    };
    if (rule.effect !== undefined) out.effect = rule.effect;
    if (rule.fields !== undefined) out.fields = rule.fields;
    if (rule.priority !== undefined) out.priority = rule.priority;
    if (rule.description !== undefined) out.description = rule.description;
    return out;
  });

  const compiled = permissions.compiled;
  const result: { -readonly [K in keyof SerializedPolicy]: SerializedPolicy[K] } = {
    version: 1,
    options: policy.options,
    roles: policy.roles,
    resources: policy.resources,
    rules,
    __hasConditions: hasConditions,
  };
  if (compiled.id !== undefined) result.id = compiled.id;
  return result;
}
