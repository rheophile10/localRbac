// Sealed box — encrypt a payload to a recipient's X25519 public key so only they
// can open it (read control: data-keys sealed to each reader). WebCrypto X25519
// ECDH (native, ~8–46× faster than pure-JS) + HKDF + AES-256-GCM. Async.
// Anonymous-sender: an ephemeral keypair per seal; the recipient reconstructs
// the shared secret from the ephemeral public key. unseal needs the recipient's
// OWN public key too (WebCrypto cannot derive it from the private key) — the
// Identity carries it.
import { toHex, fromHex, utf8, concat, randomBytes } from '../util';

export const NAME = 'webcrypto/x25519-sealedbox';

// PKCS8 wrapper for a raw 32-byte X25519 private scalar (OID 1.3.101.110).
const X25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const ALG = { name: 'X25519' } as const;

const importPriv = (scalar: Uint8Array): Promise<CryptoKey> => {
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(X25519_PKCS8_PREFIX);
  pkcs8.set(scalar, X25519_PKCS8_PREFIX.length);
  return crypto.subtle.importKey('pkcs8', pkcs8.slice().buffer, ALG, false, ['deriveBits']);
};
const importPub = (pub: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey('raw', pub.slice().buffer, ALG, false, []);

const ecdh = async (priv: CryptoKey, peerPub: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: await importPub(peerPub) }, priv, 256));

const hkdf32 = async (ikm: Uint8Array, info: Uint8Array): Promise<Uint8Array> => {
  const key = await crypto.subtle.importKey('raw', ikm.slice().buffer, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0).buffer, info: info.slice().buffer }, key, 256));
};
const aesEncrypt = async (key: Uint8Array, data: Uint8Array): Promise<{ n: string; c: string }> => {
  const k = await crypto.subtle.importKey('raw', key.slice().buffer, 'AES-GCM', false, ['encrypt']);
  const nonce = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce.slice().buffer }, k, data.slice().buffer));
  return { n: toHex(nonce), c: toHex(ct) };
};
const aesDecrypt = async (key: Uint8Array, n: string, c: string): Promise<Uint8Array> => {
  const k = await crypto.subtle.importKey('raw', key.slice().buffer, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(n).slice().buffer }, k, fromHex(c).slice().buffer));
};

/** Generate a fresh X25519 keypair; returns the 32-byte scalar + hex public. */
export const generateKeypair = async (): Promise<{ scalar: Uint8Array; pub: string }> => {
  const kp = await crypto.subtle.generateKey(ALG, true, ['deriveBits']) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return { scalar: pkcs8.slice(pkcs8.length - 32), pub: toHex(raw) };
};

/** Seal `data` to a recipient's X25519 public key (hex). */
export const seal = async (recipientPubHex: string, data: Uint8Array): Promise<string> => {
  const recipientPub = fromHex(recipientPubHex);
  const eph = await crypto.subtle.generateKey(ALG, true, ['deriveBits']) as CryptoKeyPair;
  const ephPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: await importPub(recipientPub) }, eph.privateKey, 256));
  const key = await hkdf32(shared, concat(concat(ephPub, recipientPub), utf8('seal')));
  const { n, c } = await aesEncrypt(key, data);
  return JSON.stringify({ e: toHex(ephPub), n, c });
};

/** Open a sealed box with the recipient's private scalar + own public key. */
export const unseal = async (recipientScalar: Uint8Array, recipientPubHex: string, boxStr: string): Promise<Uint8Array> => {
  const { e, n, c } = JSON.parse(boxStr) as { e: string; n: string; c: string };
  const ephPub = fromHex(e);
  const shared = await ecdh(await importPriv(recipientScalar), ephPub);
  const key = await hkdf32(shared, concat(concat(ephPub, fromHex(recipientPubHex)), utf8('seal')));
  return aesDecrypt(key, n, c);
};
