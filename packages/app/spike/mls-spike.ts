/* Spike: prove the MLS module (ts-mls, pure TS + WebCrypto) runs in the browser
 * from a SINGLE self-contained file on file:// — no WASM, no network. Founds a
 * group, adds a member, checks both derive the same per-resource DEK, and
 * round-trips an application message. Writes PASS/FAIL to #out for the e2e. */
import { mls } from '@localrbac/datalayer';

const out = document.querySelector('#out') as HTMLElement;
const lines: string[] = [];
const log = (m: string): void => { lines.push(m); out.textContent = lines.join('\n'); };
const hex = (u: Uint8Array): string => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');

const run = async (): Promise<void> => {
  log('protocol: no network — location = ' + location.protocol);
  const suite = await mls.mlsSuite();
  log('ciphersuite: ' + mls.MLS_SUITE);

  const alice = await mls.createIdentity('alice', suite);
  const bob = await mls.createIdentity('bob', suite);
  log('generated key packages for alice + bob');

  let ag = await mls.foundGroup('clinic-team', alice, suite);
  const add = await mls.addMember(ag, bob.publicPackage, suite);
  ag = add.group;
  const bg = await mls.joinFromWelcome(add.welcome, bob, ag.ratchetTree, suite);
  log('group founded; bob joined at epoch ' + mls.epoch(ag).toString());

  const dA = await mls.resourceDek(ag, 'patient:alice', suite);
  const dB = await mls.resourceDek(bg, 'patient:alice', suite);
  const agree = hex(dA) === hex(dB) && dA.length === 32 && !/^0+$/.test(hex(dA));
  log('group DEK agreement: ' + (agree ? 'yes' : 'NO') + ' (' + hex(dA).slice(0, 16) + '…)');

  const sent = await mls.send(ag, new TextEncoder().encode('the eagle lands at dawn'), suite);
  const got = await mls.receive(bg, sent.message, suite);
  const roundtrip = got.kind === 'application' && new TextDecoder().decode(got.plaintext) === 'the eagle lands at dawn';
  log('application message round-trip: ' + (roundtrip ? 'ok' : 'FAILED'));

  log(agree && roundtrip ? 'PASS' : 'FAIL');
};

run().catch((e) => { log('ERROR: ' + (e as Error).message); log('FAIL'); });
