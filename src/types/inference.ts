import type { PolicyDefinition } from './policy.js';
import type { ResourceInstance } from './instances.js';

/** All role names declared in a policy literal. */
export type InferRoles<P extends PolicyDefinition> = keyof P['roles'] & string;

/** All resource names declared in a policy literal. */
export type InferResources<P extends PolicyDefinition> = keyof P['resources'] & string;

/** Actions declared on a specific resource. */
export type InferActions<
  P extends PolicyDefinition,
  R extends InferResources<P>,
> = P['resources'][R] extends { actions: readonly (infer A)[] } ? A & string : never;

/** Reverse map: `{ post: 'read'|'create'|...; comment: 'read'|... }`. */
export type ActionsByResource<P extends PolicyDefinition> = {
  [R in InferResources<P>]: InferActions<P, R>;
};

/** Per-resource concrete instance shapes (for typed `target`). */
export type ResourceInstanceMap<P extends PolicyDefinition> = {
  [R in InferResources<P>]: ResourceInstance;
};

/** Default permissive instance map used when the consumer doesn't supply one. */
export type DefaultInstances<P extends PolicyDefinition> = {
  [R in InferResources<P>]: ResourceInstance;
};
