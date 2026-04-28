import type { InferConditions } from './inference.js';
import type {
  PolicySpec,
  ResourceDef,
  ResourcePermissions,
  RoleDef,
} from './policy.js';

/**
 * Walks a literal `P extends PolicySpec` and rebinds every cross-reference
 * (`extends`, action keys, condition refs) to its actual literal union.
 *
 * Intersected with the user spec at the `definePolicy<const P>(spec: P &
 * ValidatePolicy<P>)` boundary so mistyped keys become a TypeScript error
 * at the policy-definition site, not a silent runtime deny.
 *
 * See plan §4.1 / §4.3 for the catch list (typo'd resource, typo'd action,
 * unknown role in `extends`, unknown condition in `when`).
 */
export type ValidatePolicy<P extends PolicySpec> = {
  readonly roles: {
    readonly [R in keyof P['roles']]: RoleDef<keyof P['roles'] & string>;
  };
  readonly permissions: {
    readonly [R in keyof P['permissions']]?: {
      readonly [Res in keyof P['resources']]?: P['resources'][Res] extends ResourceDef
        ? ResourcePermissions<P['resources'][Res], InferConditions<P>>
        : never;
    };
  };
};
