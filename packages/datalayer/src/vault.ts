/* ============================================================================
 * vault.ts — threshold-custody "seal / unlock ceremony".
 *
 * Lock a payload (e.g. a full database dump) so that NO single person can open
 * it — only a quorum of k-of-n custodians cooperating:
 *
 *   sealVault(payload, custodians, k):
 *     1. random data-key (DEK)
 *     2. encrypt payload under DEK (xchacha20poly1305)
 *     3. Shamir-split DEK into n shares
 *     4. seal share i to custodian i's X25519 public key   (reuses our identities)
 *     -> a SealedVault (JSON, no secret recoverable below quorum)
 *
 *   unlock = each of >=k custodians contributes their unsealed share, then
 *            openVault() combines them -> DEK -> decrypts the payload.
 *
 * Shamir only controls WHO can reassemble the DEK; confidentiality rests on the
 * AEAD. The DEK is zeroed immediately after use.
 * ==========================================================================*/
import * as C from './crypto';
import type { Identity } from './types';
import type { Share } from './crypto';

export interface Custodian {
  name: string;
  xPub: string; // X25519 public key (hex) — from the user's identity
}

export interface SealedVault {
  v: 1;
  kind: 'sealed-vault';
  aead: string;
  sharing: string;
  k: number;
  n: number;
  ciphertext: string; // AEAD blob of the payload under the random DEK
  custodians: Array<{ name: string; x: number; pub: string; wrapped: string }>;
}

export interface ContributedShare {
  name: string;
  share: Share;
}

/** k-of-n quorum from a ratio (default 0.8 → 4-of-5). */
export const quorumFor = (n: number, ratio = 0.8): number =>
  Math.max(1, Math.min(n, Math.ceil(ratio * n)));

/** Lock a payload to a k-of-n custodian quorum. */
export const sealVault = async (payload: Uint8Array, custodians: Custodian[], k: number): Promise<SealedVault> => {
  const n = custodians.length;
  if (k < 1 || k > n) throw new Error('require 1 <= k <= n');
  const dek = C.randomKey();
  const ciphertext = await C.aeadEncryptBytes(dek, payload);
  const shares = C.splitSecret(dek, k, n);
  const wrapped = await Promise.all(custodians.map(async (c, i) => ({
    name: c.name,
    x: shares[i].x,
    pub: c.xPub,
    wrapped: await C.sealTo(c.xPub, C.packShare(shares[i])), // sealed to this custodian only
  })));
  dek.fill(0);
  return { v: 1, kind: 'sealed-vault', aead: C.PROTOCOLS.aead, sharing: C.PROTOCOLS.sharing, k, n, ciphertext, custodians: wrapped };
};

/** Public info for an unlock UI — quorum + who the custodians are. No secrets. */
export const readVaultInfo = (vault: SealedVault): { k: number; n: number; custodians: Array<{ name: string; x: number }> } =>
  ({ k: vault.k, n: vault.n, custodians: vault.custodians.map((c) => ({ name: c.name, x: c.x })) });

/** A custodian "sits down" and contributes their share (unsealed with their key).
 *  Returns null if this identity is not a custodian of the vault. */
export const contributeShare = async (vault: SealedVault, identity: Identity): Promise<ContributedShare | null> => {
  const entry = vault.custodians.find((c) => c.pub === identity.xPub);
  if (!entry) return null;
  const packed = await C.unseal(identity.xPriv, identity.xPub, entry.wrapped);
  return { name: entry.name, share: C.unpackShare(packed) };
};

/* ---- Distributed unlock (no hot-seat) ----------------------------------
 * Each custodian, at their own machine, re-seals their share to the chosen
 * OPENER's key, producing a contribution file. The opener imports k of them
 * (plus their own share) and opens the vault. Reproduces regina's model. */

/** A custodian produces a contribution for `openerXPub` — their share re-sealed
 *  so only the opener can read it. Throws if they aren't a custodian. */
export const produceContribution = async (vault: SealedVault, contributor: Identity, openerXPubHex: string): Promise<string> => {
  const c = await contributeShare(vault, contributor);
  if (!c) throw new Error('not a custodian of this vault');
  return C.sealTo(openerXPubHex, C.packShare(c.share));
};

/** The opener opens one contribution file with their key → a share. Throws if it
 *  wasn't sealed to them, or the share isn't in this vault's roster. */
export const importContribution = async (vault: SealedVault, box: string, opener: Identity): Promise<ContributedShare> => {
  let packed: Uint8Array;
  try { packed = await C.unseal(opener.xPriv, opener.xPub, box); }
  catch { throw new Error('not a contribution for you (wrong opener, or corrupt)'); }
  const share = C.unpackShare(packed);
  const entry = vault.custodians.find((cu) => cu.x === share.x);
  if (!entry) throw new Error('contribution does not match any custodian in this vault');
  return { name: entry.name, share };
};

/** Combine >=k contributed shares to reconstruct the DEK and decrypt the payload.
 *  Throws if fewer than k shares or if reconstruction/auth fails. */
export const openVault = async (vault: SealedVault, contributions: ContributedShare[]): Promise<Uint8Array> => {
  const shares = contributions.map((c) => c.share);
  if (shares.length < vault.k) throw new Error(`need ${vault.k} shares, have ${shares.length}`);
  const dek = C.combineShares(shares);
  try {
    return await C.aeadDecryptBytes(dek, vault.ciphertext);
  } catch {
    throw new Error('unlock failed (wrong or insufficient shares, or tampered vault)');
  } finally {
    dek.fill(0);
  }
};
