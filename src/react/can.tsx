import type * as React from 'react';
import type { InferActions, InferResources } from '../types/inference.js';
import type { PolicySpec } from '../types/policy.js';
import { type UseCanArgs, useCan } from './use-can.js';

/**
 * Props accepted by the `<Can>` gate component.
 *
 * Children render only when `useCan(args)` resolves to `true`; the
 * optional `fallback` renders otherwise.
 */
export type CanProps<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
> = UseCanArgs<P, R, A> & {
  readonly children: React.ReactNode;
  readonly fallback?: React.ReactNode;
};

/**
 * Conditional gate that mirrors `enforcer.check` at render time.
 *
 * @example
 *   <Can resource="document" action="delete" data={doc} fallback={<Disabled />}>
 *     <DeleteButton />
 *   </Can>
 */
export function Can<
  P extends PolicySpec,
  R extends InferResources<P>,
  A extends InferActions<P, R>,
>(props: CanProps<P, R, A>): React.ReactElement | null {
  const { children, fallback, ...args } = props;
  const allowed = useCan(args as UseCanArgs<P, R, A>);
  if (allowed) return children as React.ReactElement;
  return (fallback ?? null) as React.ReactElement | null;
}
