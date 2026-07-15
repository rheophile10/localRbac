// Digital signatures — WebCrypto Ed25519 (native, ~6.5–63× faster than pure-JS).
// Async. Keys are GENERATED (not derived from a seed): the public key comes back
// from generateKey and is stored in the keystore, so we never need seed→pubkey
// derivation (which WebCrypto can't do) — this is what lets us drop noble.
import { toHex } from '../util';

export const NAME = 'webcrypto/ed25519';

// ASN.1 PKCS8 prefix for an Ed25519 private key; the 32-byte seed follows.
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const ALG = { name: 'Ed25519' } as const;

// Cache imported CryptoKeys so we import each seed / public key at most once.
const privCache = new Map<string, Promise<CryptoKey>>();
const pubCache = new Map<string, Promise<CryptoKey>>();

// Copy into a fresh ArrayBuffer-backed view so the strict BufferSource DOM
// types accept it (a Uint8Array may be SharedArrayBuffer-backed in general).
const buf = (u: Uint8Array): ArrayBuffer => u.slice().buffer;

const importPriv = (seed: Uint8Array): Promise<CryptoKey> => {
  const id = toHex(seed);
  let p = privCache.get(id);
  if (!p) {
    const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + 32);
    pkcs8.set(PKCS8_PREFIX);
    pkcs8.set(seed, PKCS8_PREFIX.length);
    p = crypto.subtle.importKey('pkcs8', buf(pkcs8), ALG, false, ['sign']);
    privCache.set(id, p);
  }
  return p;
};
const importPub = (pub: Uint8Array): Promise<CryptoKey> => {
  const id = toHex(pub);
  let p = pubCache.get(id);
  if (!p) { p = crypto.subtle.importKey('raw', buf(pub), ALG, false, ['verify']); pubCache.set(id, p); }
  return p;
};

// Generate a fresh Ed25519 keypair; returns the 32-byte seed + hex public key.
export const generateKeypair = async (): Promise<{ seed: Uint8Array; pub: string }> => {
  const kp = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return { seed: pkcs8.slice(pkcs8.length - 32), pub: toHex(raw) };
};

export const sign = async (message: Uint8Array, priv: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.sign(ALG, await importPriv(priv), buf(message)));

export const verify = async (sig: Uint8Array, message: Uint8Array, pub: Uint8Array): Promise<boolean> =>
  crypto.subtle.verify(ALG, await importPub(pub), buf(sig), buf(message));
