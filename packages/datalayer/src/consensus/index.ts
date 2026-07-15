/* consensus segment — pure verbs over the checkpoint chain. One verb per export,
 * value→value, no effects (a future plastron lockedlambda segment). The sidecar
 * `consensus.catalog.json` holds each verb's contract; keys match these exports. */
export { chainFrom, tip, mergeBase, isDescendant, mergeVV } from './chain';
export type { Checkpoint } from './chain';

export const SEGMENT = 'consensus' as const;
