/* Step 1: consensus checkpoints + diff-since-checkpoint + merge-base.
 * Pure chain verbs + the cr-engine checkpoint chain and incremental export. */
import { describe, it, expect, beforeAll } from 'vitest';
import { nodeCrEngine } from './helpers/boot-node';
import { createCrDevice, type CrDevice } from '../src/engine/crengine';
import { addRecord } from './helpers/records';
import * as consensus from '../src/consensus';

let engine: Awaited<ReturnType<typeof nodeCrEngine>>;
beforeAll(async () => { engine = await nodeCrEngine(); });
const dev = (l: string) => createCrDevice(engine, l);
const provision = async (admin: CrDevice, user: CrDevice, role: 'reader' | 'writer'): Promise<void> => {
  await admin.importIdentityCard(await user.exportIdentityCard());
  await admin.grant(user.session!.edPub, role);
};

describe('consensus pure verbs (chain / merge-base)', () => {
  const cps: consensus.Checkpoint[] = [
    { hash: 'g', epoch: 0, parent: '' },
    { hash: 'c1', epoch: 1, parent: 'g' },
    { hash: 'c2', epoch: 2, parent: 'c1' },
    { hash: 'c3', epoch: 3, parent: 'c2' },
  ];
  it('chainFrom walks to root; tip is highest epoch', () => {
    expect(consensus.chainFrom(cps, 'c2')).toEqual(['c2', 'c1', 'g']);
    expect(consensus.chainFrom(cps, 'nope')).toEqual([]);
    expect(consensus.tip(cps)).toBe('c3');
  });
  it('mergeBase finds the most-recent common checkpoint', () => {
    // a fork: c2a off c1 alongside c2/c3
    const forked = [...cps, { hash: 'c2a', epoch: 2, parent: 'c1' }];
    expect(consensus.mergeBase(forked, 'c3', 'c2a')).toBe('c1'); // common ancestor
    expect(consensus.mergeBase(cps, 'c3', 'c2')).toBe('c2');     // c2 is on c3's chain
    expect(consensus.isDescendant(cps, 'c3', 'g')).toBe(true);
  });
});

describe('cr-engine checkpoints + diff-since-checkpoint', () => {
  it('records a checkpoint chain; exportSince yields only newer ops; peer converges', async () => {
    const admin = dev('admin');
    await admin.login('admin'); await admin.genesis();
    const alice = dev('alice'); await alice.login('alice');
    await provision(admin, alice, 'writer');
    await alice.syncFrom(admin);

    // checkpoint c1 over the initial state
    await addRecord(admin, 'note-A', 'first');
    const c1 = await admin.recordCheckpoint();
    expect(await admin.latestCheckpoint()).toBe(c1);
    expect((await admin.checkpoints()).map((c) => c.epoch)).toContain(0);

    // more ops AFTER c1
    await addRecord(admin, 'note-B', 'second');

    // exportSince(c1) carries only the post-c1 ops; a fresh reader converges
    const diff = await admin.exportSince(c1);
    expect(diff).toContain('crsql_changes');            // has content
    expect(diff.length).toBeLessThan((await admin.exportChangeset(-1)).length); // smaller than full

    // alice already had the c1 state; applying the diff brings her note-B
    const before = (await alice.listRecords()).length;
    await alice.importChangeset(diff);
    const after = await alice.listRecords();
    expect(after.length).toBeGreaterThanOrEqual(before);
    expect(after.some((n) => n.cols.body === 'second')).toBe(true);

    // the checkpoint chain travels: alice sees c1 after a full sync
    await alice.syncFrom(admin);
    expect((await alice.checkpoints()).some((c) => c.hash === c1)).toBe(true);

    await admin.close(); await alice.close();
  });

  it('a non-admin cannot record a checkpoint', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const bob = dev('bob'); await bob.login('bob');
    await provision(admin, bob, 'writer');
    await bob.syncFrom(admin);
    await expect(bob.recordCheckpoint()).rejects.toThrow(/admin only/);
    await admin.close(); await bob.close();
  });

  it('merge-confirm: import returns a state root; bidirectional sync converges', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const wanda = dev('wanda'); await wanda.login('wanda');
    await provision(admin, wanda, 'writer');
    await wanda.syncFrom(admin);

    // both write concurrently → diverged
    await addRecord(admin, 'a', 'from admin');
    await addRecord(wanda, 'w', 'from wanda');
    expect(consensus.converged(await admin.stateRoot(), await wanda.stateRoot())).toBe(false);

    // one-way push isn't enough; bidirectional sync converges
    const r1 = await admin.syncFrom(wanda); // admin pulls wanda
    const r2 = await wanda.syncFrom(admin); // wanda pulls admin
    expect(r1.applied && r2.applied).toBe(true);

    const [ra, rw] = [await admin.stateRoot(), await wanda.stateRoot()];
    expect(consensus.converged(ra, rw)).toBe(true);   // merge-confirmed
    expect(r2.stateRoot).toBe(ra);                     // the returned root matches
    await admin.close(); await wanda.close();
  });
});
