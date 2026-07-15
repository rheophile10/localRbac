/* compartment segment — public verbs. One exported function per verb, each a
 * pure value→value transform (a future plastron lockedlambda cel). The sidecar
 * `compartment.catalog.json` holds each verb's one-sentence contract; the keys
 * there line up 1:1 with these exports. */
export {
  recordKey,
  foldRecords,
  recordResources,
  visibleRecords,
  canConsolidate,
  resourcesOf,
} from './materialize';
export type { DecryptedCell, ResourceTag } from './materialize';

export const SEGMENT = 'compartment' as const;
