/* ============================================================================
 * ceremony/index.ts — the lock / unlock / distribute ceremony.
 *
 * Pure record verbs are re-exported from ./records; the functions HERE are
 * crypto-EFFECTFUL orchestration (they seal, encrypt, and use randomness), kept
 * separate from the pure verbs per plastron discipline.
 *
 * LOCK (needs archive + backup keys; locker must hold ALL resource DEKs):
 *   → active vault (k-of-n custodians) + archive (to archival key) + backup diff
 *     (to backup key). Archived records are split out of the active truth.
 * UNLOCK: distributed (vault.produceContribution / importContribution / openVault).
 * DISTRIBUTE: per-user slice sealed to each user's key.
 * ==========================================================================*/
import * as C from '../crypto';
import { sealVault, type Custodian, type SealedVault } from '../vault';
import type { Identity } from '../types';
import { partition, sliceForResources, resourcesIn, serialize, deserialize, type ConsolidatedRecord } from './records';

export * from './records';

export interface LockInput {
  records: ConsolidatedRecord[];
  held: ReadonlySet<string>; // resources the locker holds DEKs for
  custodians: Custodian[]; // active-vault quorum
  threshold: number; // k
  archivePubHex: string; // archival X25519 public key (required)
  backupPubHex: string; // backup X25519 public key (required)
  dayDiff: Uint8Array; // the day's consolidated delta (for the backup)
}

export interface LockOutput {
  activeVault: SealedVault; // k-of-n custodians
  archiveSealed: string; // sealed to the archival key
  backupSealed: string; // the day-diff, sealed to the backup key
  counts: { active: number; archived: number };
}

/** Close-out lock. Refuses without both custody keys, and refuses unless the
 *  locker holds a DEK for every resource present (the patient/doctor gate). */
export const lock = async (input: LockInput): Promise<LockOutput> => {
  if (!input.archivePubHex) throw new Error('archive public key required to begin locking');
  if (!input.backupPubHex) throw new Error('backup public key required to begin locking');
  for (const res of resourcesIn(input.records)) {
    if (!input.held.has(res)) throw new Error(`cannot lock: locker is missing the DEK for resource "${res}"`);
  }
  const { active, archived } = partition(input.records);
  return {
    activeVault: await sealVault(serialize(active), input.custodians, input.threshold),
    archiveSealed: await C.sealTo(input.archivePubHex, serialize(archived)),
    backupSealed: await C.sealTo(input.backupPubHex, input.dayDiff),
    counts: { active: active.length, archived: archived.length },
  };
};

/** Open the archive dump — only the holder of the archival private key can. */
export const openArchive = async (archiveSealed: string, archivist: Identity): Promise<ConsolidatedRecord[]> =>
  deserialize(await C.unseal(archivist.xPriv, archivist.xPub, archiveSealed));

/** Read the plaintext consolidated active records after the quorum opened the
 *  vault (openVault → these bytes). */
export const readActive = (payload: Uint8Array): ConsolidatedRecord[] => deserialize(payload);

export interface SliceRecipient {
  name: string;
  xPubHex: string; // recipient's X25519 public key
  readable: string[]; // resources they may read (from grants)
}
export interface DistributedSlice {
  name: string;
  count: number;
  sealed: string; // slice sealed to the recipient's key
}

/** DISTRIBUTE — for each recipient, a slice of only their permitted records,
 *  sealed to their key. Only that recipient can open it. */
export const distribute = (records: ConsolidatedRecord[], recipients: SliceRecipient[]): Promise<DistributedSlice[]> =>
  Promise.all(recipients.map(async (u) => {
    const slice = sliceForResources(records, new Set(u.readable));
    return { name: u.name, count: slice.length, sealed: await C.sealTo(u.xPubHex, serialize(slice)) };
  }));

/** A recipient opens their distributed slice with their key. */
export const openSlice = async (sealed: string, recipient: Identity): Promise<ConsolidatedRecord[]> =>
  deserialize(await C.unseal(recipient.xPriv, recipient.xPub, sealed));

export const SEGMENT = 'ceremony' as const;
