/* ============================================================================
 * crypto/index.ts — the business crypto API the app consumes. Each operation
 * delegates to a functional domain (kdf / signing / sealing / aead / hash),
 * and each domain picks a concrete implementation in its own index.ts.
 *
 * All asymmetric + symmetric crypto is WebCrypto (native, fast, no dependency);
 * only the memory-hard KDF (Argon2id) is hash-wasm. NO @noble. Identities are
 * GENERATED and kept in an Argon2id-wrapped keystore (see keystore.ts) — public
 * keys are stored, never re-derived, which is what lets us avoid noble.
 *
 *   kdf      -> hash-wasm Argon2id      (memory-hard keystore wrapping)
 *   signing  -> WebCrypto Ed25519       (write authorization)
 *   sealing  -> WebCrypto X25519 box    (read control: seal data-key to a reader)
 *   aead     -> WebCrypto AES-256-GCM   (record + payload encryption)
 *   hash     -> WebCrypto SHA-256/HKDF  (state root + key expansion)
 * ==========================================================================*/
import type { Identity } from '../types';
import * as util from './util';
import * as kdf from './kdf';
import * as signing from './signing';
import * as sealing from './sealing';
import * as aead from './aead';
import * as hash from './hash';
import * as sharing from './secret-sharing';

// byte/encoding helpers
export const { utf8, fromUtf8, toHex, fromHex, short } = util;

// content hash (state root). Async (WebCrypto). EMPTY_ROOT is the precomputed
// hash of '' so callers don't need to await for the empty case.
export const sha256hex = hash.sha256hex;
export const EMPTY_ROOT = hash.EMPTY_SHA256;

export const PROTOCOLS = {
  kdf: kdf.NAME, signing: signing.NAME, sealing: sealing.NAME,
  aead: aead.NAME, hash: hash.NAME, sharing: sharing.NAME,
} as const;

// Threshold secret sharing (split a data-key k-of-n).
export type { Share } from './secret-sharing';
export const splitSecret = sharing.split;
export const combineShares = sharing.combine;
export const packShare = sharing.packShare;
export const unpackShare = sharing.unpackShare;
export const randomKey = (): Uint8Array => util.randomBytes(32);

/* ---- Identity: freshly GENERATED (not derived) ---------------------------
 * WebCrypto generateKey gives us the keypairs + public keys; we keep the private
 * seeds (raw bytes) for on-demand WebCrypto import. Persist via the keystore. */
export const createIdentity = async (name: string): Promise<Identity> => {
  const ed = await signing.generateKeypair();
  const x = await sealing.generateKeypair();
  return { name, edPriv: ed.seed, xPriv: x.scalar, edPub: ed.pub, xPub: x.pub };
};

// KDF passthrough (keystore wrapping key from a passphrase).
export const deriveKey = kdf.deriveKey;

// Keystore: wrap a generated identity under a passphrase (a downloadable file —
// never stored in the browser). createKeystore/loadKeystore/migrateKeystore.
export { createKeystore, loadKeystore, migrateKeystore } from './keystore';
export type { KeystoreBlob } from './keystore';

// Detached signature over an arbitrary string message (a CRR row, a changeset,
// an identity card). Async — WebCrypto Ed25519.
export const signMessage = async (message: string, edPriv: Uint8Array): Promise<string> =>
  util.toHex(await signing.sign(util.utf8(message), edPriv));
export const verifyMessage = async (message: string, sigHex: string, authorHex: string): Promise<boolean> => {
  try { return await signing.verify(util.fromHex(sigHex), util.utf8(message), util.fromHex(authorHex)); }
  catch { return false; }
};

// Compartment data-key: one DEK per (resource, version), from a 32-byte root key.
export const deriveResourceDEK = (rootKey: Uint8Array, resource: string, ver: number): Promise<Uint8Array> =>
  hash.hkdf(rootKey, util.utf8('dek:' + resource), util.utf8('v' + ver), 32);

// At-rest DB key for the IndexedDB VFS, from the session's signing seed.
export const deriveVaultKey = (edPriv: Uint8Array): Promise<Uint8Array> =>
  hash.hkdf(edPriv, util.utf8('localrbac-vfs-salt'), util.utf8('at-rest-db'), 32);

// Read control: seal a data-key to a reader's public key / open your own.
export const sealTo = (recipientXPubHex: string, data: Uint8Array): Promise<string> =>
  sealing.seal(recipientXPubHex, data);
export const unseal = (recipientXPriv: Uint8Array, recipientXPubHex: string, box: string): Promise<Uint8Array> =>
  sealing.unseal(recipientXPriv, recipientXPubHex, box);

// Record encryption under a data-key (AES-256-GCM).
export const aeadEncrypt = (key: Uint8Array, plaintext: string): Promise<string> => aead.encrypt(key, plaintext);
export const aeadDecrypt = (key: Uint8Array, blob: string): Promise<string> => aead.decrypt(key, blob);
export const aeadEncryptBytes = (key: Uint8Array, data: Uint8Array): Promise<string> => aead.encryptBytes(key, data);
export const aeadDecryptBytes = (key: Uint8Array, blob: string): Promise<Uint8Array> => aead.decryptBytes(key, blob);
