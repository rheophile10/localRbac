/* Step 3: DEK rotation decoupled from revoke (optional).
 * Also closes red-team RT-REVOKE on the cr-engine: a revoked reader keeps data
 * they already had the key for, but is locked out of writes AFTER rotation. */
import { describe, it, expect, beforeAll } from 'vitest';
import { nodeCrEngine } from './helpers/boot-node';
import { createCrDevice, type CrDevice } from '../src/engine/crengine';
import { addRecord } from './helpers/records';

let engine: Awaited<ReturnType<typeof nodeCrEngine>>;
beforeAll(async () => { engine = await nodeCrEngine(); });
const dev = (l: string) => createCrDevice(engine, l);
const provision = async (admin: CrDevice, user: CrDevice, role: 'reader' | 'writer'): Promise<void> => {
  await admin.importIdentityCard(await user.exportIdentityCard());
  await admin.grant(user.session!.edPub, role);
};
const bodyOf = async (d: CrDevice, id: string): Promise<string | null> =>
  ((await d.listRecords()).find((n) => n.id === id)?.cols.body) ?? null; // locked/absent → null

describe('DEK rotation (optional) + revocation', () => {
  it('RT-REVOKE: revoke WITH rotation → old readable, new locked to the revoked user', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const alice = dev('alice'); await alice.login('alice');
    await provision(admin, alice, 'reader');
    await alice.syncFrom(admin);

    const oldNote = await addRecord(admin, 'old', 'before revoke');
    await alice.syncFrom(admin);
    expect(await bodyOf(alice, oldNote)).toBe('before revoke'); // reader can read

    // revoke alice (rotate=true by default) → DEK bumps, not re-sealed to her
    await admin.revoke(alice.session!.edPub); // resource defaults to 'default'
    const newNote = await addRecord(admin, 'new', 'after revoke');
    await alice.syncFrom(admin);

    expect(await bodyOf(alice, oldNote)).toBe('before revoke'); // still has old key
    expect(await bodyOf(alice, newNote)).toBeNull();            // new version locked to her
    await admin.close(); await alice.close();
  });

  it('revoke WITHOUT rotation → the revoked user still reads new writes (the option matters)', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const bob = dev('bob'); await bob.login('bob');
    await provision(admin, bob, 'reader');
    await bob.syncFrom(admin);

    await admin.revoke(bob.session!.edPub, 'default', false); // no rotation
    const n = await addRecord(admin, 'n', 'still visible');
    await bob.syncFrom(admin);
    expect(await bodyOf(bob, n)).toBe('still visible'); // same DEK version → still readable
    await admin.close(); await bob.close();
  });

  it('rotateDek: a standalone rotation keeps current members reading; rotateAllDeks covers every resource', async () => {
    const admin = dev('admin'); await admin.login('admin'); await admin.genesis();
    const wanda = dev('wanda'); await wanda.login('wanda');
    await provision(admin, wanda, 'writer');
    await wanda.syncFrom(admin);

    const before = await addRecord(admin, 'b', 'v1');
    await admin.rotateDek('default'); // consensus-style rotation, re-seals to wanda
    const after = await addRecord(admin, 'a', 'v2');
    await wanda.syncFrom(admin);
    // wanda is still a member → gets the new keywrap → reads both
    expect(await bodyOf(wanda, before)).toBe('v1');
    expect(await bodyOf(wanda, after)).toBe('v2');

    await admin.rotateAllDeks(); // no throw; rotates every resource
    const third = await addRecord(admin, 'c', 'v3');
    await wanda.syncFrom(admin);
    expect(await bodyOf(wanda, third)).toBe('v3');

    // a non-admin cannot rotate
    await expect(wanda.rotateDek('default')).rejects.toThrow(/admin only/);
    await admin.close(); await wanda.close();
  });
});
