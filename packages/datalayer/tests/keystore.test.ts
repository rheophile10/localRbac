/* Keystore file: create, load, migrate (re-key) — a user-held file, never
 * stored in the browser. Wrong passphrase fails closed. */
import { describe, it, expect } from 'vitest';
import * as C from '../src/crypto';

describe('keystore file', () => {
  it('round-trips an identity through a passphrase-wrapped blob', async () => {
    const id = await C.createIdentity('alice');
    const blob = await C.createKeystore(id, 'correct horse');
    expect(blob.edPub).toBe(id.edPub); // public keys travel in the clear

    const loaded = await C.loadKeystore(blob, 'correct horse');
    expect(loaded.edPub).toBe(id.edPub);
    expect(loaded.xPub).toBe(id.xPub);
    expect(Array.from(loaded.edPriv)).toEqual(Array.from(id.edPriv));
    expect(Array.from(loaded.xPriv)).toEqual(Array.from(id.xPriv));
  });

  it('a wrong passphrase fails to unwrap (fails closed)', async () => {
    const blob = await C.createKeystore(await C.createIdentity('bob'), 'pw-one');
    await expect(C.loadKeystore(blob, 'pw-two')).rejects.toThrow();
  });

  it('migrate re-keys to a NEW file (same identity, new passphrase, fresh salt/iv)', async () => {
    const id = await C.createIdentity('carol');
    const v1 = await C.createKeystore(id, 'old-pass');
    const v2 = await C.migrateKeystore(v1, 'old-pass', 'new-pass');

    expect(v2.salt).not.toBe(v1.salt); // fresh salt
    expect(v2.iv).not.toBe(v1.iv);     // fresh iv
    expect(v2.edPub).toBe(id.edPub);   // same identity

    // new file opens with the new passphrase; not the old
    expect((await C.loadKeystore(v2, 'new-pass')).edPub).toBe(id.edPub);
    await expect(C.loadKeystore(v2, 'old-pass')).rejects.toThrow();
    // migrating with the wrong old passphrase fails closed
    await expect(C.migrateKeystore(v1, 'wrong-old', 'whatever')).rejects.toThrow();
  });
});
