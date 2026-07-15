/* @localrbac/datalayer — headless CRDT + crypto-RBAC engine on cr-sqlite.
 * No DOM, no build tooling. The UI package consumes this. */
export type { Identity, Role, KnownUser } from './types';
export * as crypto from './crypto';
export { short } from './crypto';

// cr-sqlite engine (the current engine): compartmented RBAC on a CRDT extension.
export { createCrDevice } from './engine/crengine';
export type { CrEngine, CrDevice, IdentityCard, ImportResult as CrImportResult } from './engine/crengine';
export { bootBrowserEngine } from './engine/boot-browser';
export type { BrowserEngineOptions } from './engine/boot-browser';
export { Conn, createEngine } from './engine/sqlite';

// Threshold-custody vault: seal a payload k-of-n, unlock by quorum (distributed).
export {
  sealVault, readVaultInfo, contributeShare, openVault, quorumFor,
  produceContribution, importContribution,
} from './vault';
export type { Custodian, SealedVault, ContributedShare } from './vault';

// Compartmented-RBAC pure verbs.
export * as compartment from './compartment';

// Lock / unlock / distribute / archive / backup ceremony.
export * as ceremony from './ceremony';
export type { ConsolidatedRecord, LockInput, LockOutput, SliceRecipient, DistributedSlice } from './ceremony';
