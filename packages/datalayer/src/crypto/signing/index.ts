/* Signing domain — write-authorization proofs. A keypair derives from a 32-byte
 * seed (deterministic identities). sign/verify are ASYNC (WebCrypto Ed25519,
 * native and fast). Swap curve/impl by changing the one re-export line below;
 * `noble.ts` remains as a sync-JS reference implementation. */
export interface SigningProvider {
  NAME: string;
  generateKeypair: () => Promise<{ seed: Uint8Array; pub: string }>;
  sign: (message: Uint8Array, priv: Uint8Array) => Promise<Uint8Array>;
  verify: (sig: Uint8Array, message: Uint8Array, pub: Uint8Array) => Promise<boolean>;
}
export { NAME, generateKeypair, sign, verify } from './webcrypto';
