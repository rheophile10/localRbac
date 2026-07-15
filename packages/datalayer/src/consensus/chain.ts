/* ============================================================================
 * consensus/chain.ts — PURE verbs over the checkpoint chain (plastron-ready).
 * No time, no randomness, no I/O, no mutation. Hashing/signing/DB live at the
 * effect site (crengine); these verbs reason over already-materialized data.
 *
 * A checkpoint chain is a parent-linked list of agreed group states. Two
 * replicas that share history share a prefix of this chain; the merge-base is
 * the most recent checkpoint both hold.
 * ==========================================================================*/

/** A checkpoint node (the fields the pure verbs need). */
export interface Checkpoint {
  hash: string;
  epoch: number;
  parent: string; // '' at the root
}

/** `(checkpoints, hash)` — walk parent links from `hash` to the root, newest
 *  first. Returns [] if `hash` isn't present. Pure. */
export const chainFrom = (checkpoints: Checkpoint[], hash: string): string[] => {
  const byHash = new Map(checkpoints.map((c) => [c.hash, c]));
  const out: string[] = [];
  let h = hash;
  while (h && byHash.has(h)) { out.push(h); h = byHash.get(h)!.parent; }
  return out;
};

/** `(checkpoints)` — the tip (highest epoch) hash, or '' if none. Pure. */
export const tip = (checkpoints: Checkpoint[]): string =>
  checkpoints.reduce<{ hash: string; epoch: number }>((best, c) => (c.epoch > best.epoch ? c : best), { hash: '', epoch: -1 }).hash;

/** `(checkpoints, hashA, hashB)` — the most-recent common checkpoint (merge-base)
 *  of the two chains ending at hashA and hashB, or '' if none. Pure. */
export const mergeBase = (checkpoints: Checkpoint[], hashA: string, hashB: string): string => {
  const ancestorsB = new Set(chainFrom(checkpoints, hashB));
  for (const h of chainFrom(checkpoints, hashA)) if (ancestorsB.has(h)) return h; // A is newest-first
  return '';
};

/** `(checkpoints, hash, ancestor)` — is `ancestor` on the chain from `hash`? Pure. */
export const isDescendant = (checkpoints: Checkpoint[], hash: string, ancestor: string): boolean =>
  chainFrom(checkpoints, hash).includes(ancestor);

/** `(rootA, rootB)` — merge-confirm: two replicas hold the same state iff their
 *  content hashes (state roots) are equal. Pure. */
export const converged = (rootA: string, rootB: string): boolean => rootA === rootB && rootA.length > 0;
