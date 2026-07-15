/* KDF domain — turn a low-entropy passphrase into key material, expensively.
 * Swap the implementation (e.g. back to a pure-JS Argon2, or scrypt) here. */
export interface KdfProvider {
  NAME: string;
  deriveKey: (password: Uint8Array, salt: Uint8Array, dkLen: number) => Promise<Uint8Array>;
}
export { NAME, deriveKey } from './hashwasm';
