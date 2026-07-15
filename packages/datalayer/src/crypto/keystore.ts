/* keystore.ts — persist a generated Identity under a passphrase. The private
 * seeds are wrapped with AES-256-GCM under an Argon2id(passphrase) key; the
 * public keys travel in the clear (they're public). The blob is safe to store
 * in a plain IndexedDB store or a downloadable file. Wrong passphrase → the GCM
 * tag fails → load throws (fails closed). */
import type { Identity } from '../types';
import * as util from './util';
import * as kdf from './kdf';

export interface KeystoreBlob {
  v: 1;
  kind: 'localrbac-keystore';
  name: string;
  edPub: string;
  xPub: string;
  salt: string; // hex, per-keystore
  iv: string;   // hex
  wrapped: string; // hex — AES-GCM(Argon2id(pass,salt), {edPriv,xPriv})
}

const importAes = (key: Uint8Array, use: 'encrypt' | 'decrypt'): Promise<CryptoKey> =>
  crypto.subtle.importKey('raw', key.slice().buffer, 'AES-GCM', false, [use]);

export const createKeystore = async (id: Identity, passphrase: string): Promise<KeystoreBlob> => {
  const salt = util.randomBytes(16);
  const iv = util.randomBytes(12);
  const wrapKey = await kdf.deriveKey(util.utf8(passphrase), salt, 32);
  const payload = util.utf8(JSON.stringify({ edPriv: util.toHex(id.edPriv), xPriv: util.toHex(id.xPriv) }));
  const wrapped = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv.slice().buffer }, await importAes(wrapKey, 'encrypt'), payload.slice().buffer));
  return { v: 1, kind: 'localrbac-keystore', name: id.name, edPub: id.edPub, xPub: id.xPub,
    salt: util.toHex(salt), iv: util.toHex(iv), wrapped: util.toHex(wrapped) };
};

export const loadKeystore = async (blob: KeystoreBlob, passphrase: string): Promise<Identity> => {
  const wrapKey = await kdf.deriveKey(util.utf8(passphrase), util.fromHex(blob.salt), 32);
  const plain = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: util.fromHex(blob.iv).slice().buffer }, await importAes(wrapKey, 'decrypt'),
    util.fromHex(blob.wrapped).slice().buffer));
  const { edPriv, xPriv } = JSON.parse(util.fromUtf8(plain)) as { edPriv: string; xPriv: string };
  return { name: blob.name, edPub: blob.edPub, xPub: blob.xPub, edPriv: util.fromHex(edPriv), xPriv: util.fromHex(xPriv) };
};

/** Migrate a keystore to a NEW file under a new passphrase (fresh salt + IV) —
 *  same identity, so all existing grants/data still apply. Wrong old passphrase
 *  fails to unwrap (fails closed). */
export const migrateKeystore = async (blob: KeystoreBlob, oldPassphrase: string, newPassphrase: string): Promise<KeystoreBlob> =>
  createKeystore(await loadKeystore(blob, oldPassphrase), newPassphrase);
