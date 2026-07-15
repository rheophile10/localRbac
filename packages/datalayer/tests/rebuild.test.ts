/* Step 4: the wipe-and-rebuild consensus loop.
 * Coordinator merges member diffs → optional DEK rotation → records a checkpoint
 * → hands each member a slice of their entitled, non-archived records. Member
 * wipes local store and rebuilds from the slice. */
import { describe, it, expect, beforeAll } from 'vitest';
import { nodeCrEngine } from './helpers/boot-node';
import { createCrDevice, type CrDevice } from '../src/engine/crengine';

let engine: Awaited<ReturnType<typeof nodeCrEngine>>;
beforeAll(async () => { engine = await nodeCrEngine(); });
const dev = (l: string) => createCrDevice(engine, l);
const provision = async (admin: CrDevice, user: CrDevice, role: 'reader' | 'writer', resource?: string): Promise<void> => {
  await admin.importIdentityCard(await user.exportIdentityCard());
  await admin.grant(user.session!.edPub, role, resource);
};
const bodies = async (d: CrDevice): Promise<(string | null)[]> => (await d.listNotes()).map((n) => n.body);

describe('wipe-and-rebuild consensus loop', () => {
  it('a member rebuilds from a slice of only their entitled, non-archived records', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const alice = dev('alice'); await alice.login('alice');
    await provision(admin, alice, 'reader', 'patient:alice');
    await alice.syncFrom(admin);

    // records across two compartments + one archived
    await admin.addNote('AliceActive', 'a-live', 'patient:alice');
    const old = await admin.addNote('AliceOld', 'a-old', 'patient:alice');
    await admin.addNote('BobActive', 'b-live', 'patient:bob');
    await admin.archiveRecord(old, true);

    // consensus: (no member diffs here) rotate + checkpoint
    const cp = await admin.runConsensus([], { rotate: true });
    expect(cp).toHaveLength(64); // sha256 hex

    // alice's rebuild slice: her resource, non-archived only
    const slice = await admin.rebuildSliceFor(alice.session!.edPub);

    // alice WIPES and rebuilds from the slice
    await alice.wipe();
    const res = await alice.importChangeset(slice);
    expect(res.applied).toBe(true);

    const notes = await alice.listNotes();
    const titles = notes.map((n) => n.body);
    expect(titles).toContain('a-live');       // her active record, readable
    expect(titles).not.toContain('a-old');    // archived → excluded from the slice
    expect(titles).not.toContain('b-live');   // bob's compartment → not in her slice
    // and she can actually decrypt her record (rotation re-sealed her key)
    expect(notes.find((n) => n.body === 'a-live')?.body).toBe('a-live');

    await admin.close(); await alice.close();
  });

  it('runConsensus merges a writer\'s diff-since-checkpoint before checkpointing', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const wanda = dev('wanda'); await wanda.login('wanda');
    await provision(admin, wanda, 'writer');
    await wanda.syncFrom(admin);

    // baseline checkpoint, then wanda writes since it
    const c0 = await admin.recordCheckpoint();
    await wanda.syncFrom(admin); // wanda gets c0
    await wanda.addNote('field', 'wanda was here');

    // wanda exports her diff since c0; coordinator runs consensus with it
    const diff = await wanda.exportSince(c0);
    const c1 = await admin.runConsensus([diff], { rotate: false });
    expect(c1).not.toBe(c0);
    expect((await admin.checkpoints()).length).toBeGreaterThanOrEqual(2);
    expect(await bodies(admin)).toContain('wanda was here'); // merged + decrypted

    await admin.close(); await wanda.close();
  });

  it('a non-admin cannot build slices or run consensus', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const bob = dev('bob'); await bob.login('bob');
    await provision(admin, bob, 'reader');
    await bob.syncFrom(admin);
    await expect(bob.rebuildSliceFor(bob.session!.edPub)).rejects.toThrow(/admin only/);
    await expect(bob.runConsensus([])).rejects.toThrow(/admin only/);
    await admin.close(); await bob.close();
  });
});
