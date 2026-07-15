/* The full compartmented-RBAC engine on cr-sqlite (async, :memory: in Node).
 * Identities are generated (keystore model); provisioning is by public-key
 * card exchange — admin never sees a user's private material. */
import { describe, it, expect, beforeAll } from 'vitest';
import { nodeCrEngine } from './helpers/boot-node';
import { createCrDevice, type CrDevice } from '../src/engine/crengine';

let engine: Awaited<ReturnType<typeof nodeCrEngine>>;
beforeAll(async () => { engine = await nodeCrEngine(); });
const dev = (label: string) => createCrDevice(engine, label);

// admin imports a user's card and grants them a role on a resource
const provision = async (admin: CrDevice, user: CrDevice, role: 'reader' | 'writer', resource?: string): Promise<string> => {
  await admin.importIdentityCard(await user.exportIdentityCard());
  await admin.grant(user.session!.edPub, role, resource);
  return user.session!.edPub;
};

describe('cr-sqlite compartmented-RBAC engine', () => {
  it('card-exchange provisioning, per-resource notes, sync, compartment reads', async () => {
    const admin = dev('admin');
    await admin.login('admin');
    await admin.genesis();
    expect(await admin.myRole()).toBe('admin');

    // alice logs in on her own device (generates her identity), shares her card
    const alice = dev('alice');
    await alice.login('alice');
    const alicePub = await provision(admin, alice, 'reader', 'patient:alice');

    const aliceChart = await admin.addNote('Alice chart', 'BP 120/80', 'patient:alice');
    await admin.addNote('Bob chart', 'BP 140/90', 'patient:bob');

    // alice syncs admin's state → gets her grant + keywrap + the encrypted notes.
    // Her grant is on 'patient:alice' (not the default 'notes'), so myRole (which
    // is notes-scoped) is 'none' — but she holds the patient:alice DEK.
    expect((await alice.syncFrom(admin)).applied).toBe(true);
    expect(alice.session!.edPub).toBe(alicePub);

    // alice sees her chart decrypted; bob's is locked (not in her readable set)
    const notes = await alice.listNotes();
    expect(notes.find((n) => n.id === aliceChart)?.body).toBe('BP 120/80');
    expect(notes.every((n) => n.body !== 'BP 140/90')).toBe(true);
    expect(await alice.heldResources()).toContain('patient:alice');
    expect(await alice.heldResources()).not.toContain('patient:bob');

    // admin holds all DEKs → consolidates both compartments to plaintext
    const consolidated = await admin.consolidate();
    expect(consolidated.map((r) => r.cols.title).sort()).toEqual(['Alice chart', 'Bob chart']);
    const bob = consolidated.find((r) => r.cols.title === 'Bob chart')!;
    expect(bob.resources).toEqual(['patient:bob']);
    expect(bob.cols.body).toBe('BP 140/90');

    await admin.close(); await alice.close();
  });

  it('writer writes and it converges back to admin; reader cannot write', async () => {
    const admin = dev('admin');
    await admin.login('admin');
    await admin.genesis();

    const wanda = dev('wanda'); await wanda.login('wanda');
    const rick = dev('rick'); await rick.login('rick');
    await provision(admin, wanda, 'writer');
    await provision(admin, rick, 'reader');

    await wanda.syncFrom(admin);
    expect(await wanda.myRole()).toBe('writer');
    const nid = await wanda.addNote('Field note', 'the eagle has landed');

    // admin imports wanda's change → converges, decrypts
    expect((await admin.syncFrom(wanda)).applied).toBe(true);
    expect((await admin.listNotes()).find((n) => n.id === nid)?.body).toBe('the eagle has landed');

    // reader rick cannot write
    await rick.syncFrom(admin);
    expect(await rick.myRole()).toBe('reader');
    await expect(rick.addNote('nope', 'denied')).rejects.toThrow(/DENIED/);

    await admin.close(); await wanda.close(); await rick.close();
  });

  it('rejects a forged identity card and a self-appointed admin at import', async () => {
    const admin = dev('admin');
    await admin.login('admin');
    await admin.genesis();

    // a self-appointed admin (own genesis) → conflicting admin root, rejected
    const mallory = dev('mallory');
    await mallory.login('mallory');
    await mallory.genesis(); // mallory is admin of HER OWN db
    await mallory.addNote('forged', 'nope');
    const forged = await mallory.exportChangeset(-1);

    const bob = dev('bob');
    await bob.login('bob');
    await provision(admin, bob, 'reader');
    await bob.syncFrom(admin); // pins the real admin
    const res = await bob.importChangeset(forged);
    expect(res.applied).toBe(false);
    expect(res.rejected.join(' ')).toMatch(/conflicting admin root/);

    await admin.close(); await mallory.close(); await bob.close();
  });

  it('idempotent import; an un-granted observer sees rows but locked bodies', async () => {
    const admin = dev('admin');
    await admin.login('admin');
    await admin.genesis();
    await admin.addNote('n1', 'one');
    const cs = await admin.exportChangeset(-1);

    const q = dev('q');
    await q.login('q-observer');
    expect((await q.importChangeset(cs)).applied).toBe(true);
    expect((await q.importChangeset(cs)).applied).toBe(true); // twice = idempotent
    // q is not admin/granted → the note exists but its body is locked (no DEK)
    const notes = await q.listNotes();
    expect(notes).toHaveLength(1);
    expect(notes[0].body).toBeNull();

    await admin.close(); await q.close();
  });
});
