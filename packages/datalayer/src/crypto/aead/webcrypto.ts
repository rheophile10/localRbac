// Symmetric authenticated encryption — AES-256-GCM (WebCrypto, native, ~10×
// faster than pure-JS xchacha at file://). Async. The 32-byte key is imported
// per call; blobs are JSON { n: nonce(12B hex), c: ciphertext+tag hex }.
import { toHex, fromHex, utf8, fromUtf8, randomBytes } from '../util';

export const NAME = 'webcrypto/aes-256-gcm';

const importKey = (key: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey('raw', key.slice().buffer, 'AES-GCM', false, ['encrypt', 'decrypt']);

const enc = async (key: Uint8Array, data: Uint8Array): Promise<string> => {
  const k = await importKey(key);
  const nonce = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce.slice().buffer }, k, data.slice().buffer));
  return JSON.stringify({ n: toHex(nonce), c: toHex(ct) });
};
const dec = async (key: Uint8Array, blob: string): Promise<Uint8Array> => {
  const { n, c } = JSON.parse(blob) as { n: string; c: string };
  const k = await importKey(key);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(n).slice().buffer }, k, fromHex(c).slice().buffer));
};

export const encrypt = (key: Uint8Array, plaintext: string): Promise<string> => enc(key, utf8(plaintext));
export const decrypt = async (key: Uint8Array, blob: string): Promise<string> => fromUtf8(await dec(key, blob));
export const encryptBytes = (key: Uint8Array, data: Uint8Array): Promise<string> => enc(key, data);
export const decryptBytes = (key: Uint8Array, blob: string): Promise<Uint8Array> => dec(key, blob);
