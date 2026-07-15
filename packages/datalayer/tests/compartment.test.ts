import { describe, it, expect } from 'vitest';
import * as C from '../src/crypto';
import { foldRecords, recordKey, recordResources, visibleRecords, canConsolidate, type DecryptedCell, type ResourceTag } from '../src/compartment';

// An encrypted cell-write as it lives in the log: val is ciphertext under ONE
// resource's DEK, so a record edited under two resources has two ciphertexts.
interface EncOp { tbl: string; rowId: string; col: string; resource: string; hlc: string; ct: string }

describe('compartment model (per-resource ciphertexts, RBAC-scoped merge)', () => {
  it('a record tagged to two resources has two ciphertexts; each reader sees only theirs; both-DEK holder merges', async () => {
    const root = C.randomKey(); // the DEK-derivation root (admin only)
    const dekAlice = await C.deriveResourceDEK(root, 'patient:alice', 1);
    const dekBob = await C.deriveResourceDEK(root, 'patient:bob', 1);

    // record "rec1" is written under alice's resource (t1) and bob's (t2>t1)
    const log: EncOp[] = [
      { tbl: 'notes', rowId: 'rec1', col: 'body', resource: 'patient:alice', hlc: '000000000000001.000000.a', ct: await C.aeadEncrypt(dekAlice, 'alice view') },
      { tbl: 'notes', rowId: 'rec1', col: 'body', resource: 'patient:bob', hlc: '000000000000002.000000.b', ct: await C.aeadEncrypt(dekBob, 'bob view') },
    ];
    expect(log).toHaveLength(2); // two ciphertexts for one record/cell

    const tags: ResourceTag[] = [
      { tbl: 'notes', rowId: 'rec1', resource: 'patient:alice' },
      { tbl: 'notes', rowId: 'rec1', resource: 'patient:bob' },
    ];
    expect(recordResources(tags, 'notes', 'rec1')).toEqual(['patient:alice', 'patient:bob']);

    // decrypt only what a holder's DEKs allow, then LWW-merge
    const decryptWith = async (keys: Map<string, Uint8Array>): Promise<DecryptedCell[]> =>
      Promise.all(log
        .filter((o) => keys.has(o.resource))
        .map(async (o) => ({ tbl: o.tbl, rowId: o.rowId, col: o.col, resource: o.resource, hlc: o.hlc, value: await C.aeadDecrypt(keys.get(o.resource)!, o.ct) })));

    const bodyOf = (cells: DecryptedCell[]): string | null | undefined =>
      foldRecords(cells).get(recordKey('notes', 'rec1'))?.get('body');

    expect(bodyOf(await decryptWith(new Map([['patient:alice', dekAlice]])))).toBe('alice view');
    expect(bodyOf(await decryptWith(new Map([['patient:bob', dekBob]])))).toBe('bob view');
    const both = new Map([['patient:alice', dekAlice], ['patient:bob', dekBob]]);
    expect(bodyOf(await decryptWith(both))).toBe('bob view'); // both DEKs → LWW picks bob (t2)
  });

  it('RBAC visibility and the "lock needs all DEKs" gate', () => {
    const tags: ResourceTag[] = [
      { tbl: 'notes', rowId: 'r1', resource: 'patient:alice' },
      { tbl: 'notes', rowId: 'r2', resource: 'patient:bob' },
      { tbl: 'notes', rowId: 'r3', resource: 'patient:alice' },
    ];
    // a holder of only alice's resource sees r1 and r3, not r2
    expect(visibleRecords(tags, new Set(['patient:alice'])).map((r) => r.rowId)).toEqual(['r1', 'r3']);
    // consolidation gate: needs DEKs for EVERY resource present
    expect(canConsolidate(tags, new Set(['patient:alice']))).toBe(false);
    expect(canConsolidate(tags, new Set(['patient:alice', 'patient:bob']))).toBe(true);
  });
});
