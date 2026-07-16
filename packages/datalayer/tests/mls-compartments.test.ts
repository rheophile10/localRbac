/* Per-resource MLS groups as the keywrap replacement. The load-bearing property:
 * one group per resource preserves compartmentalization — a member of resource A
 * cannot derive resource B's DEK, because they hold no group state for B. */
import { describe, it, expect, beforeAll } from 'vitest';
import * as mls from '../src/mls';

const hex = (u: Uint8Array | null) => (u ? Buffer.from(u).toString('hex') : null);

let suite: mls.MlsSuite;
beforeAll(async () => { suite = await mls.mlsSuite(); });

describe('mls compartments (keywrap replacement)', () => {
  it('grants per resource; members derive their DEKs; compartments stay isolated', async () => {
    const adminId = await mls.createIdentity('admin', suite);
    const aliceId = await mls.createIdentity('alice', suite);
    const bobId = await mls.createIdentity('bob', suite);

    const admin = mls.createCoordinatorCompartments(adminId, suite);
    const alice = mls.createMemberCompartments(aliceId, suite);
    const bob = mls.createMemberCompartments(bobId, suite);

    // alice granted patient:alice; bob granted patient:bob (disjoint compartments)
    await alice.join(await admin.grant('patient:alice', aliceId.publicPackage));
    await bob.join(await admin.grant('patient:bob', bobId.publicPackage));

    // each member derives the SAME DEK the coordinator holds for their resource
    expect(hex(await alice.dek('patient:alice'))).toBe(hex(await admin.dek('patient:alice')));
    expect(hex(await bob.dek('patient:bob'))).toBe(hex(await admin.dek('patient:bob')));

    // COMPARTMENT ISOLATION: alice has no state for patient:bob → DEK underivable
    expect(alice.has('patient:bob')).toBe(false);
    expect(await alice.dek('patient:bob')).toBeNull();
    expect(bob.has('patient:alice')).toBe(false);
    expect(await bob.dek('patient:alice')).toBeNull();

    // and the two compartments' DEKs are unrelated
    expect(hex(await admin.dek('patient:alice'))).not.toBe(hex(await admin.dek('patient:bob')));
  });

  it('a second member of the same resource agrees; revoke rotates the DEK', async () => {
    const adminId = await mls.createIdentity('admin', suite);
    const aliceId = await mls.createIdentity('alice', suite);
    const bobId = await mls.createIdentity('bob', suite);

    const admin = mls.createCoordinatorCompartments(adminId, suite);
    const alice = mls.createMemberCompartments(aliceId, suite);
    const bob = mls.createMemberCompartments(bobId, suite);

    // alice joins notes (leaf 1), then bob joins notes (leaf 2)
    const gAlice = await admin.grant('notes', aliceId.publicPackage);
    await alice.join(gAlice);
    const gBob = await admin.grant('notes', bobId.publicPackage);
    await bob.join(gBob);
    // alice must apply bob's add-commit to reach the same epoch as admin + bob
    await alice.apply('notes', gBob.commit);

    const dekWithBoth = hex(await admin.dek('notes'));
    expect(hex(await alice.dek('notes'))).toBe(dekWithBoth);
    expect(hex(await bob.dek('notes'))).toBe(dekWithBoth);

    // revoke bob (leaf index 2) → epoch advances → DEK rotates away from him
    const rev = await admin.revoke('notes', 2);
    await alice.apply('notes', rev.commit);
    const dekAfter = hex(await admin.dek('notes'));
    expect(dekAfter).not.toBe(dekWithBoth);
    expect(hex(await alice.dek('notes'))).toBe(dekAfter); // alice stays in sync
    expect(hex(await bob.dek('notes'))).toBe(dekWithBoth); // bob stuck at the old, now-dead epoch
  });
});
