/* ============================================================================
 * compartment/materialize.ts — PURE verbs for the compartmented RBAC CRDT.
 *
 * No time, no randomness, no I/O, no mutation of inputs — every function is a
 * pure value→value transform, so it can later be lifted into plastron as a
 * lockedlambda cel (see ../README.md). Time (`hlc`) and keys are passed IN.
 *
 * Model: a record may be tagged to many resources; each cell-write is encrypted
 * under one resource's data-key, so a record has up to N ciphertexts. A holder
 * sees a record's state as the Last-Writer-Wins merge across ONLY the
 * resource-versions they can decrypt.
 * ==========================================================================*/

/** One decrypted cell-write the holder was able to open (from some resource). */
export interface DecryptedCell {
  tbl: string;
  rowId: string;
  col: string;
  resource: string;
  hlc: string; // sortable logical clock — determines the LWW winner
  value: string | null; // decrypted value (null = tombstone)
}

/** A record↔resource tag (the index-table row). */
export interface ResourceTag {
  tbl: string;
  rowId: string;
  resource: string;
}

const SEP = ''; // unit separator — cannot occur in our ids

/** `(tbl, rowId)` — the stable key foldRecords() uses for a record. Pure. */
export const recordKey = (tbl: string, rowId: string): string => tbl + SEP + rowId;
const cellKey = (c: { tbl: string; rowId: string; col: string }): string => c.tbl + SEP + c.rowId + SEP + c.col;

/** `(cells)` — LWW fold: the highest-hlc write wins per (tbl,rowId,col), merging
 *  ACROSS resources. Returns recordKey(tbl,rowId) → (col → value). Pure. */
export const foldRecords = (cells: DecryptedCell[]): Map<string, Map<string, string | null>> => {
  const winner = new Map<string, DecryptedCell>();
  for (const c of cells) {
    const k = cellKey(c);
    const w = winner.get(k);
    if (!w || c.hlc > w.hlc) winner.set(k, c);
  }
  const records = new Map<string, Map<string, string | null>>();
  for (const c of winner.values()) {
    const rk = recordKey(c.tbl, c.rowId);
    let rec = records.get(rk);
    if (!rec) { rec = new Map(); records.set(rk, rec); }
    rec.set(c.col, c.value);
  }
  return records;
};

/** `(tags, tbl, rowId)` — the sorted set of resources a record is tagged to. Pure. */
export const recordResources = (tags: ResourceTag[], tbl: string, rowId: string): string[] =>
  [...new Set(tags.filter((t) => t.tbl === tbl && t.rowId === rowId).map((t) => t.resource))].sort();

/** `(tags, held)` — records visible to a holder of `held` resources: those tagged
 *  to at least one held resource. Deterministic order (first tag seen). Pure. */
export const visibleRecords = (tags: ResourceTag[], held: ReadonlySet<string>): Array<{ tbl: string; rowId: string }> => {
  const seen = new Set<string>();
  const out: Array<{ tbl: string; rowId: string }> = [];
  for (const t of tags) {
    if (!held.has(t.resource)) continue;
    const k = recordKey(t.tbl, t.rowId);
    if (!seen.has(k)) { seen.add(k); out.push({ tbl: t.tbl, rowId: t.rowId }); }
  }
  return out;
};

/** `(tags, held)` — true iff EVERY tagged resource is in `held`. This is the
 *  "you can only lock what you can decrypt" gate: a locker must hold the DEKs for
 *  every resource present before it may consolidate. Pure. */
export const canConsolidate = (tags: ResourceTag[], held: ReadonlySet<string>): boolean =>
  tags.every((t) => held.has(t.resource));

/** `(tags)` — the distinct resources referenced by a tag set. Pure. */
export const resourcesOf = (tags: ResourceTag[]): string[] =>
  [...new Set(tags.map((t) => t.resource))].sort();
