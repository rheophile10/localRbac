/* MLS module: RFC 9420 group key agreement + messaging via the src/mls verbs.
 * Pure TS + WebCrypto, headless, no WASM/network — the file:// spike, promoted. */
import { describe, it, expect, beforeAll } from 'vitest';
import * as mls from '../src/mls';

const utf8 = (s: string) => new TextEncoder().encode(s);
const utf8d = (u: Uint8Array) => new TextDecoder().decode(u);
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');

let suite: mls.MlsSuite;
beforeAll(async () => { suite = await mls.mlsSuite(); });

describe('mls module', () => {
  it('founds a group, adds a member, agrees a per-resource DEK, messages round-trip', async () => {
    const alice = await mls.createIdentity('alice', suite);
    const bob = await mls.createIdentity('bob', suite);

    let ag = await mls.foundGroup('clinic-team', alice, suite);
    const add = await mls.addMember(ag, bob.publicPackage, suite);
    ag = add.group;
    let bg = await mls.joinFromWelcome(add.welcome, bob, ag.ratchetTree, suite);

    // group key agreement: both derive the SAME resource DEK at this epoch
    const [dA, dB] = await Promise.all([
      mls.resourceDek(ag, 'patient:alice', suite),
      mls.resourceDek(bg, 'patient:alice', suite),
    ]);
    expect(hex(dA)).toBe(hex(dB));
    expect(dA).toHaveLength(32);
    expect(hex(dA)).not.toMatch(/^0+$/);
    expect(mls.epoch(ag)).toBe(mls.epoch(bg));

    // different resource ⇒ different DEK from the same epoch secret
    const dOther = await mls.resourceDek(ag, 'patient:bob', suite);
    expect(hex(dOther)).not.toBe(hex(dA));

    // application message alice → bob
    const sent = await mls.send(ag, utf8('the eagle lands at dawn'), suite);
    ag = sent.group;
    const got = await mls.receive(bg, sent.message, suite);
    bg = got.group;
    expect(got.kind).toBe('application');
    if (got.kind === 'application') expect(utf8d(got.plaintext)).toBe('the eagle lands at dawn');
  });

  it('rotates the group DEK on membership change; all members reconverge', async () => {
    const alice = await mls.createIdentity('alice', suite);
    const bob = await mls.createIdentity('bob', suite);
    const carol = await mls.createIdentity('carol', suite);

    let ag = await mls.foundGroup('g', alice, suite);
    const a1 = await mls.addMember(ag, bob.publicPackage, suite);
    ag = a1.group;
    let bg = await mls.joinFromWelcome(a1.welcome, bob, ag.ratchetTree, suite);
    const dekBefore = hex(await mls.resourceDek(ag, 'notes', suite));

    // add carol: commit goes to bob, welcome to carol
    const a2 = await mls.addMember(ag, carol.publicPackage, suite);
    ag = a2.group;
    bg = await mls.applyCommit(bg, a2.commit, suite);
    const cg = await mls.joinFromWelcome(a2.welcome, carol, ag.ratchetTree, suite);

    const [eA, eB, eC] = await Promise.all([
      mls.resourceDek(ag, 'notes', suite),
      mls.resourceDek(bg, 'notes', suite),
      mls.resourceDek(cg, 'notes', suite),
    ]);
    expect(hex(eA)).toBe(hex(eB));
    expect(hex(eB)).toBe(hex(eC));
    expect(hex(eA)).not.toBe(dekBefore); // new epoch ⇒ rotated DEK
  });

  it('removing a member advances the epoch and rotates the DEK', async () => {
    const alice = await mls.createIdentity('alice', suite);
    const bob = await mls.createIdentity('bob', suite);

    let ag = await mls.foundGroup('g', alice, suite);
    const add = await mls.addMember(ag, bob.publicPackage, suite);
    ag = add.group;
    const dekWithBob = hex(await mls.resourceDek(ag, 'notes', suite));
    const e0 = mls.epoch(ag);

    // bob is the second leaf (index 1); remove him
    const rm = await mls.removeMember(ag, 1, suite);
    ag = rm.group;
    expect(mls.epoch(ag)).toBe(e0 + 1n);
    expect(hex(await mls.resourceDek(ag, 'notes', suite))).not.toBe(dekWithBob);
  });
});
