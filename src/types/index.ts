export type {
  PolicyDefinition,
  Rule,
  RuleFor,
  WildcardRule,
  RuleLike,
  RoleDefinition,
  ResourceDefinition,
  PolicyOptions,
  NormalizedRule,
} from './policy.js';
export type { Subject } from './subject.js';
export type { Decision, DecisionReason, MatchedRule } from './decision.js';
export type { ConditionFn, ConditionArgs, DeclarativeCondition } from './condition.js';
export type { ResourceInstance } from './instances.js';
export type {
  InferRoles,
  InferResources,
  InferActions,
  ActionsByResource,
  ResourceInstanceMap,
  DefaultInstances,
} from './inference.js';
export type { CheckArgs, AbilityCheckArgs, AnyResourceAction } from './check-args.js';
