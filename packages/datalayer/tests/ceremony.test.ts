import { describe, it, expect, beforeAll } from 'vitest';
import * as C from '../src/crypto';
import {
  quorumFor, produceContribution, importContribution, openVault,
  contributeShare, type Custodian,
} from '../src/vault';
import * as ceremony from '../src/ceremony';
import type { ConsolidatedRecord } from '../src/ceremony';
import type { Identity } from '../src/types';

const ids: Record<string, Identity> = {};
beforeAll(async () => {
  for (const n of ['op', 'c2', 'c3', 'archivist', 'backup', 'alice', 'bob']) ids[n] = await C.createIdentity(n);
});
const custOf = (names: string[]): Custodian[] => names.map((n) => ({ name: n, xPub: ids[n].xPub }));

const REC: ConsolidatedRecord[] = [
  { tbl: 'notes', rowId: 'r1', cols: { body: 'alice-only' }, resources: ['patient:alice'], archived: false },
  { tbl: 'notes', rowId: 'r2', cols: { body: 'bob-only' }, resources: ['patient:bob'], archived: false },
  { tbl: 'notes', rowId: 'r3', cols: { body: 'shared' }, resources: ['patient:alice', 'patient:bob'], archived: false },
  { tbl: 'notes', rowId: 'r4', cols: { body: 'old case' }, resources: ['patient:alice'], archived: true },
];
const ALL = new Set(['patient:alice', 'patient:bob']);
const keys = () => ({ archivePubHex: ids.archivist.xPub, backupPubHex: ids.backup.xPub });

describe('ceremony — lock / distributed unlock / distribute (happy paths)', () => {
  it('DL-8 lock emits active vault + archive + backup; archived split out', async () => {
    const out = await ceremony.lock({
      records: REC, held: ALL, custodians: custOf(['op', 'c2', 'c3']), threshold: quorumFor(3),
      ...keys(), dayDiff: new TextEncoder().encode('day-delta'),
    });
    expect(out.counts).toEqual({ active: 3, archived: 1 });
    expect((await ceremony.openArchive(out.archiveSealed, ids.archivist)).map((r) => r.rowId)).toEqual(['r4']);
    expect(C.fromUtf8(await C.unseal(ids.backup.xPriv, ids.backup.xPub, out.backupSealed))).toBe('day-delta');
  });

  it('DL-7 distributed unlock: opener seeds their share, imports contributions, opens', async () => {
    const out = await ceremony.lock({ records: REC, held: ALL, custodians: custOf(['op', 'c2', 'c3']), threshold: quorumFor(3), ...keys(), dayDiff: new Uint8Array([1]) });
    const vault = out.activeVault;
    const own = (await contributeShare(vault, ids.op))!;
    const b2 = await produceContribution(vault, ids.c2, ids.op.xPub);
    const b3 = await produceContribution(vault, ids.c3, ids.op.xPub);
    const shares = [own, await importContribution(vault, b2, ids.op), await importContribution(vault, b3, ids.op)];
    const active = ceremony.readActive(await openVault(vault, shares));
    expect(active.map((r) => r.rowId).sort()).toEqual(['r1', 'r2', 'r3']);
  });

  it('DL-9 distribute: each user gets only their permitted records, sealed to them', async () => {
    const active = REC.filter((r) => !r.archived);
    const slices = await ceremony.distribute(active, [
      { name: 'alice', xPubHex: ids.alice.xPub, readable: ['patient:alice'] },
      { name: 'bob', xPubHex: ids.bob.xPub, readable: ['patient:bob'] },
    ]);
    const aliceSlice = await ceremony.openSlice(slices.find((s) => s.name === 'alice')!.sealed, ids.alice);
    const bobSlice = await ceremony.openSlice(slices.find((s) => s.name === 'bob')!.sealed, ids.bob);
    expect(aliceSlice.map((r) => r.rowId).sort()).toEqual(['r1', 'r3']);
    expect(bobSlice.map((r) => r.rowId).sort()).toEqual(['r2', 'r3']);
  });
});

describe('ceremony — failure stories (fails closed)', () => {
  const base = () => ({ records: REC, held: ALL, custodians: custOf(['op', 'c2', 'c3']), threshold: 3, dayDiff: new Uint8Array([1]) });

  it('FL-1 / FL-2 lock refuses without archive or backup key', async () => {
    await expect(ceremony.lock({ ...base(), archivePubHex: '', backupPubHex: ids.backup.xPub })).rejects.toThrow(/archive public key/);
    await expect(ceremony.lock({ ...base(), archivePubHex: ids.archivist.xPub, backupPubHex: '' })).rejects.toThrow(/backup public key/);
  });

  it('FL-3 lock refuses if the locker lacks a resource DEK', async () => {
    await expect(ceremony.lock({ ...base(), held: new Set(['patient:alice']), ...keys() }))
      .rejects.toThrow(/missing the DEK for resource "patient:bob"/);
  });

  it('FL-4 sub-quorum cannot open the vault', async () => {
    const out = await ceremony.lock({ ...base(), ...keys() });
    const own = (await contributeShare(out.activeVault, ids.op))!;
    await expect(openVault(out.activeVault, [own])).rejects.toThrow(); // 1 < 3
  });

  it('FL-5 a non-custodian cannot produce a contribution', async () => {
    const out = await ceremony.lock({ ...base(), ...keys() });
    await expect(produceContribution(out.activeVault, ids.alice, ids.op.xPub)).rejects.toThrow(/not a custodian/);
    expect(await contributeShare(out.activeVault, ids.alice)).toBeNull();
  });

  it('FL-6 a contribution for opener A cannot be imported by opener B', async () => {
    const out = await ceremony.lock({ ...base(), ...keys() });
    const forOp = await produceContribution(out.activeVault, ids.c2, ids.op.xPub);
    await expect(importContribution(out.activeVault, forOp, ids.c3)).rejects.toThrow(/not a contribution for you/);
  });

  it('FL-7 a tampered vault fails to open', async () => {
    const out = await ceremony.lock({ ...base(), ...keys() });
    const shares = [(await contributeShare(out.activeVault, ids.op))!, (await contributeShare(out.activeVault, ids.c2))!, (await contributeShare(out.activeVault, ids.c3))!];
    const tampered = { ...out.activeVault, ciphertext: out.activeVault.ciphertext.replace(/..$/, '00') };
    await expect(openVault(tampered, shares)).rejects.toThrow();
  });

  it('FL-8 a share from a different vault is rejected on import', async () => {
    const a = (await ceremony.lock({ ...base(), ...keys() })).activeVault;
    const b = (await ceremony.lock({ ...base(), ...keys() })).activeVault;
    const boxFromB = await produceContribution(b, ids.c2, ids.op.xPub);
    const shares = [(await contributeShare(a, ids.op))!, await importContribution(a, boxFromB, ids.op), (await contributeShare(a, ids.c3))!];
    await expect(openVault(a, shares)).rejects.toThrow();
  });

  it('FL-11 a slice for user A cannot be opened by user B', async () => {
    const slices = await ceremony.distribute(REC.filter((r) => !r.archived), [
      { name: 'alice', xPubHex: ids.alice.xPub, readable: ['patient:alice'] },
    ]);
    await expect(ceremony.openSlice(slices[0].sealed, ids.bob)).rejects.toThrow();
  });

  it('FL-12 the archive does not open with a custodian/user key', async () => {
    const out = await ceremony.lock({ ...base(), ...keys() });
    await expect(ceremony.openArchive(out.archiveSealed, ids.op)).rejects.toThrow();
    await expect(ceremony.openArchive(out.archiveSealed, ids.alice)).rejects.toThrow();
  });
});
