/* Sealing domain — public-key "seal to a recipient" (read control). Async
 * (WebCrypto X25519 + AES-GCM). unseal needs the recipient's own public key
 * (WebCrypto can't derive it from the private key). Swap impl via the re-export. */
export interface SealingProvider {
  NAME: string;
  generateKeypair: () => Promise<{ scalar: Uint8Array; pub: string }>;
  seal: (recipientPubHex: string, data: Uint8Array) => Promise<string>;
  unseal: (recipientScalar: Uint8Array, recipientPubHex: string, box: string) => Promise<Uint8Array>;
}
export { NAME, generateKeypair, seal, unseal } from './webcrypto';
