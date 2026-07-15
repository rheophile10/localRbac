/* AEAD domain — symmetric record encryption under a data-key. Async (WebCrypto
 * AES-256-GCM). Swap cipher by changing the re-export line. */
export interface AeadProvider {
  NAME: string;
  encrypt: (key: Uint8Array, plaintext: string) => Promise<string>;
  decrypt: (key: Uint8Array, blob: string) => Promise<string>;
  encryptBytes: (key: Uint8Array, data: Uint8Array) => Promise<string>;
  decryptBytes: (key: Uint8Array, blob: string) => Promise<Uint8Array>;
}
export { NAME, encrypt, decrypt, encryptBytes, decryptBytes } from './webcrypto';
