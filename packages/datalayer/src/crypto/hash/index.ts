/* Hash domain — content hashing (state root) and HKDF key expansion. Async
 * (WebCrypto). Swap the implementation by changing the re-export line. */
export interface HashProvider {
  NAME: string;
  sha256hex: (s: string) => Promise<string>;
  hkdf: (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number) => Promise<Uint8Array>;
}
export { NAME, sha256hex, hkdf, EMPTY_SHA256 } from './webcrypto';
