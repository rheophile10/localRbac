/* ============================================================================
 * ceremony/records.ts — PURE verbs over consolidated records (plastron-style).
 * No crypto, no time, no I/O here — just partition / filter / (de)serialize.
 * The crypto-effectful orchestration lives in ./index.ts.
 * ==========================================================================*/

/** A consolidated (decrypted, LWW-merged) record, with its resource tags. */
export interface ConsolidatedRecord {
  tbl: string;
  rowId: string;
  cols: Record<string, string | null>;
  resources: string[]; // the index-table tags for this record
  archived: boolean;
}

/** `(records)` — split into active vs archived by the `archived` flag. Pure. */
export const partition = (records: ConsolidatedRecord[]): { active: ConsolidatedRecord[]; archived: ConsolidatedRecord[] } => {
  const active: ConsolidatedRecord[] = [];
  const archived: ConsolidatedRecord[] = [];
  for (const r of records) (r.archived ? archived : active).push(r);
  return { active, archived };
};

/** `(records, readable)` — the slice a holder of `readable` resources may see:
 *  records tagged to at least one readable resource. Pure. */
export const sliceForResources = (records: ConsolidatedRecord[], readable: ReadonlySet<string>): ConsolidatedRecord[] =>
  records.filter((r) => r.resources.some((res) => readable.has(res)));

/** `(records)` — every distinct resource referenced by a record set. Pure. */
export const resourcesIn = (records: ConsolidatedRecord[]): string[] =>
  [...new Set(records.flatMap((r) => r.resources))].sort();

/** `(records)` — deterministic canonical bytes of a record set (sorted), so a
 *  consolidated dump / backup is reproducible and hashable. Pure. */
export const serialize = (records: ConsolidatedRecord[]): Uint8Array => {
  const canon = records
    .map((r) => ({ tbl: r.tbl, rowId: r.rowId, cols: r.cols, resources: [...r.resources].sort(), archived: r.archived }))
    .sort((a, b) => (a.tbl + '' + a.rowId < b.tbl + '' + b.rowId ? -1 : 1));
  return new TextEncoder().encode(JSON.stringify(canon));
};

/** `(bytes)` — inverse of serialize. Pure. */
export const deserialize = (bytes: Uint8Array): ConsolidatedRecord[] =>
  JSON.parse(new TextDecoder().decode(bytes)) as ConsolidatedRecord[];
