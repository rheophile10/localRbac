import { describe, it, expect, beforeAll } from 'vitest';
import { nodeCrEngine } from './helpers/boot-node';
import { createCrDevice } from '../src/engine/crengine';
import * as C from '../src/crypto';
import { sealVault, readVaultInfo, contributeShare, openVault, quorumFor, type ContributedShare } from '../src/vault';
import type { Identity } from '../src/types';

let engine: Awaited<ReturnType<typeof nodeCrEngine>>;
beforeAll(async () => { engine = await nodeCrEngine(); });

describe('threshold-custody vault (seal / unlock ceremony)', () => {
  it('seals a real database state k-of-n; only a quorum unlocks it byte-for-byte', async () => {
    const custIds: Identity[] = [];
    for (const n of ['c1', 'c2', 'c3', 'c4', 'c5']) custIds.push(await C.createIdentity(n));
    const custodians = custIds.map((id) => ({ name: id.name, xPub: id.xPub }));
    const k = quorumFor(custodians.length); // ceil(0.8*5) = 4
    expect(k).toBe(4);

    // a real cr-sqlite database state (its full changeset) is the payload
    const admin = createCrDevice(engine, 'admin');
    await admin.login('admin');
    await admin.genesis();
    await admin.addNote('Top secret', 'the eagle lands at dawn');
    const payload = C.utf8(await admin.exportChangeset(-1));
    expect(payload.length).toBeGreaterThan(100);

    const vault = await sealVault(payload, custodians, k);
    expect(readVaultInfo(vault)).toMatchObject({ k: 4, n: 5 });

    const contribs = (await Promise.all(custIds.map((id) => contributeShare(vault, id)))).filter((c): c is ContributedShare => c !== null);
    expect(contribs).toHaveLength(5);
    expect(await contributeShare(vault, await C.createIdentity('mallory'))).toBeNull();

    // quorum (4) reconstructs and decrypts byte-for-byte
    expect(await openVault(vault, contribs.slice(0, 4))).toEqual(payload);
    // sub-quorum (3) fails closed
    await expect(openVault(vault, contribs.slice(0, 3))).rejects.toThrow();

    await admin.close();
  });

  it('a recipient-targeted merge file opens only for its recipient', async () => {
    const admin = createCrDevice(engine, 'admin');
    await admin.login('admin');
    await admin.genesis();
    await admin.addNote('shared', 'for bob only');
    const changeset = await admin.exportChangeset(-1);

    const bob = await C.createIdentity('bob');
    const dave = await C.createIdentity('dave');

    // seal the changeset to bob's key → only bob can open it
    const sealed = await C.sealTo(bob.xPub, C.utf8(changeset));
    expect(C.fromUtf8(await C.unseal(bob.xPriv, bob.xPub, sealed))).toBe(changeset);
    await expect(C.unseal(dave.xPriv, dave.xPub, sealed)).rejects.toThrow();

    await admin.close();
  });
});
