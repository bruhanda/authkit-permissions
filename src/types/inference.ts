import type { ConditionEntry } from './condition.js';
import type { PolicySpec, ResourceDef } from './policy.js';

/** Union of every role name declared in `P`. */
export type InferRoles<P extends PolicySpec> = keyof P['roles'] & string;

/** Union of every resource name declared in `P`. */
export type InferResources<P extends PolicySpec> = keyof P['resources'] & string;

/** Union of every action declared for resource `R` in `P`. */
export type InferActions<
  P extends PolicySpec,
  R extends InferResources<P>,
> = P['resources'][R] extends ResourceDef<infer A> ? A : never;

/** Union of every condition name declared in `P`. */
export type InferConditions<P extends PolicySpec> = NonNullable<P['conditions']> extends infer C
  ? C extends Record<string, ConditionEntry>
    ? keyof C & string
    : never
  : never;

/** Map of condition-name → typed function (sync or async). */
export type InferConditionMap<P extends PolicySpec> = NonNullable<P['conditions']> extends infer C
  ? C extends Record<string, ConditionEntry>
    ? { readonly [K in keyof C]: C[K] }
    : Record<string, never>
  : Record<string, never>;
