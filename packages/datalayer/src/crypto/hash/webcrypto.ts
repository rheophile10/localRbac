// Hashing — WebCrypto SHA-256 + HKDF (native, faster than pure-JS at file://).
// Async, because crypto.subtle is promise-based.
import { toHex, utf8 } from '../util';

export const NAME = 'webcrypto/sha256';

export const sha256hex = async (s: string): Promise<string> =>
  toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(s).slice().buffer)));

// Precomputed SHA-256 of the empty string (used as the empty state-root constant).
export const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export const hkdf = async (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> => {
  const key = await crypto.subtle.importKey('raw', ikm.slice().buffer, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt.slice().buffer, info: info.slice().buffer }, key, len * 8);
  return new Uint8Array(bits);
};
