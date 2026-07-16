/* ============================================================================
 * mls.ts — RFC 9420 Messaging Layer Security for a subgroup, over ts-mls.
 *
 * Pure TypeScript + WebCrypto (via @hpke/core) — no WASM, no network — so it
 * bundles into the single file:// index.html like the rest of localRbac.
 *
 * What MLS buys us on top of the compartmented-RBAC engine:
 *   - a GROUP shared secret that every member derives independently at each
 *     epoch (mlsExporter) → drives per-resource DEKs without the admin sealing
 *     a keywrap to every reader one by one.
 *   - membership changes (add / remove) advance the epoch, so the group key
 *     rotates with forward + post-compromise security "for free" — the exact
 *     "rotate the DEK at a consensus event" primitive, but group-native.
 *   - authenticated group application messages (the "messaging" of MLS).
 *
 * These are thin, side-effect-free verbs: state goes in, new state comes out
 * (ts-mls ClientState is immutable), so they drop cleanly into the plastron
 * locked-lambda / pure-cel model later. The ciphersuite and exporter label are
 * PROTOCOL CONSTANTS — every participant must match them.
 * ==========================================================================*/
import {
  getCiphersuiteImpl, getCiphersuiteFromName, generateKeyPackage,
  defaultCapabilities, defaultLifetime, emptyPskIndex,
  createGroup, createCommit, joinGroup, createApplicationMessage,
  processPrivateMessage, mlsExporter, encodeMlsMessage, decodeMlsMessage,
  zeroOutUint8Array,
} from 'ts-mls';
import type {
  CiphersuiteImpl, ClientState, KeyPackage, PrivateKeyPackage, Welcome,
  Credential, Proposal, RatchetTree, MLSMessage,
} from 'ts-mls';

// Aligns with localRbac's WebCrypto stack: X25519 + AES-128-GCM + SHA-256 + Ed25519.
export const MLS_SUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' as const;
export const DEK_LABEL = 'localrbac-dek';

export type MlsSuite = CiphersuiteImpl;
export type MlsGroup = ClientState; // immutable; verbs return a fresh one
export interface MlsIdentity { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage; }

const te = new TextEncoder();

/** Build the (async) ciphersuite implementation. Do this once and thread it. */
export const mlsSuite = (): Promise<MlsSuite> => getCiphersuiteImpl(getCiphersuiteFromName(MLS_SUITE));

/** A member's MLS identity: a signed KeyPackage (public) + its private keys.
 *  `name` becomes the basic credential — pair it with the app's Ed25519 pub. */
export const createIdentity = (name: string, suite: MlsSuite): Promise<MlsIdentity> => {
  const credential: Credential = { credentialType: 'basic', identity: te.encode(name) };
  return generateKeyPackage(credential, defaultCapabilities(), defaultLifetime, [], suite);
};

/** Found a new group as its first member. `groupId` names the subgroup. */
export const foundGroup = (groupId: string, self: MlsIdentity, suite: MlsSuite): Promise<MlsGroup> =>
  createGroup(te.encode(groupId), self.publicPackage, self.privatePackage, [], suite);

export interface AddResult { group: MlsGroup; welcome: Uint8Array; commit: Uint8Array; consumed: Uint8Array[]; }

/** Add a member by their public KeyPackage. Returns the advanced group plus the
 *  Welcome (send to the new member) and the commit (send to existing members). */
export const addMember = async (group: MlsGroup, memberPublicPackage: KeyPackage, suite: MlsSuite): Promise<AddResult> => {
  const add: Proposal = { proposalType: 'add', add: { keyPackage: memberPublicPackage } };
  // ratchetTreeExtension: the Welcome carries the tree, so a joiner needs no
  // separate out-of-band channel for it (self-contained transport).
  const r = await createCommit({ state: group, cipherSuite: suite }, { extraProposals: [add], ratchetTreeExtension: true });
  if (!r.welcome) throw new Error('add produced no welcome');
  return { group: r.newState, welcome: encodeWelcome(r.welcome), commit: encodeMessage(r.commit), consumed: r.consumed };
};

export interface RemoveResult { group: MlsGroup; commit: Uint8Array; consumed: Uint8Array[]; }

/** Remove the member at `leafIndex` (advances the epoch → the group key rotates,
 *  locking the removed member out of everything encrypted afterward). */
export const removeMember = async (group: MlsGroup, leafIndex: number, suite: MlsSuite): Promise<RemoveResult> => {
  const remove: Proposal = { proposalType: 'remove', remove: { removed: leafIndex } };
  const r = await createCommit({ state: group, cipherSuite: suite }, { extraProposals: [remove] });
  return { group: r.newState, commit: encodeMessage(r.commit), consumed: r.consumed };
};

/** Join a group from a Welcome. The ratchet tree is optional: our Welcomes
 *  embed it (ratchetTreeExtension), so pass `undefined` unless you carry it
 *  out-of-band. */
export const joinFromWelcome = (welcome: Uint8Array, self: MlsIdentity, ratchetTree: RatchetTree | undefined, suite: MlsSuite): Promise<MlsGroup> =>
  joinGroup(decodeWelcome(welcome), self.publicPackage, self.privatePackage, emptyPskIndex, suite, ratchetTree);

/** Apply someone else's commit (add / remove / update) to advance your state. */
export const applyCommit = async (group: MlsGroup, commit: Uint8Array, suite: MlsSuite): Promise<MlsGroup> => {
  const msg = decodeMessage(commit);
  if (msg.wireformat !== 'mls_private_message') throw new Error('expected a private commit');
  const r = await processPrivateMessage(group, msg.privateMessage, emptyPskIndex, suite);
  r.consumed.forEach(zeroOutUint8Array);
  if (r.kind !== 'newState') throw new Error('expected a commit, got an application message');
  return r.newState;
};

/** The current epoch (increments on every commit). */
export const epoch = (group: MlsGroup): bigint => group.groupContext.epoch;

/** Derive this group's per-resource DEK at the current epoch. Every member gets
 *  the SAME 32 bytes for the same (group, epoch, resource) — the group key
 *  agreement that can replace per-reader keywraps. Rotates with the epoch. */
export const resourceDek = (group: MlsGroup, resource: string, suite: MlsSuite, length = 32): Promise<Uint8Array> =>
  mlsExporter(group.keySchedule.exporterSecret, DEK_LABEL, te.encode('resource:' + resource), length, suite);

export interface SendResult { group: MlsGroup; message: Uint8Array; consumed: Uint8Array[]; }

/** Encrypt an authenticated application message to the group. */
export const send = async (group: MlsGroup, plaintext: Uint8Array, suite: MlsSuite): Promise<SendResult> => {
  const r = await createApplicationMessage(group, plaintext, suite);
  return { group: r.newState, message: encodeMessage({ wireformat: 'mls_private_message', version: 'mls10', privateMessage: r.privateMessage }), consumed: r.consumed };
};

export type ReceiveResult =
  | { group: MlsGroup; kind: 'application'; plaintext: Uint8Array }
  | { group: MlsGroup; kind: 'commit' };

/** Process an incoming group message: an application message (returns plaintext)
 *  or a commit (advances state). */
export const receive = async (group: MlsGroup, message: Uint8Array, suite: MlsSuite): Promise<ReceiveResult> => {
  const msg = decodeMessage(message);
  if (msg.wireformat !== 'mls_private_message') throw new Error('expected a private message');
  const r = await processPrivateMessage(group, msg.privateMessage, emptyPskIndex, suite);
  r.consumed.forEach(zeroOutUint8Array);
  return r.kind === 'applicationMessage'
    ? { group: r.newState, kind: 'application', plaintext: r.message }
    : { group: r.newState, kind: 'commit' };
};

/* ---- wire encode/decode (Uint8Array; the app layer base64s for transport) --*/
export const encodeMessage = (m: MLSMessage): Uint8Array => encodeMlsMessage(m);
export const decodeMessage = (bytes: Uint8Array): MLSMessage => {
  const d = decodeMlsMessage(bytes, 0);
  if (!d) throw new Error('undecodable MLS message');
  return d[0];
};
export const encodeKeyPackage = (kp: KeyPackage): Uint8Array => encodeMlsMessage({ wireformat: 'mls_key_package', version: 'mls10', keyPackage: kp });
export const decodeKeyPackage = (bytes: Uint8Array): KeyPackage => {
  const m = decodeMessage(bytes);
  if (m.wireformat !== 'mls_key_package') throw new Error('expected a key package');
  return m.keyPackage;
};
const encodeWelcome = (w: Welcome): Uint8Array => encodeMlsMessage({ wireformat: 'mls_welcome', version: 'mls10', welcome: w });
const decodeWelcome = (bytes: Uint8Array): Welcome => {
  const m = decodeMessage(bytes);
  if (m.wireformat !== 'mls_welcome') throw new Error('expected a welcome');
  return m.welcome;
};
