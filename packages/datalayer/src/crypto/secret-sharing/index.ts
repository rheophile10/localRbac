/* Secret-sharing domain — k-of-n threshold split of a small secret (a data-key).
 * Swap the scheme (e.g. a verifiable secret sharing) by changing the import. */
export interface Share {
  x: number;
  y: Uint8Array;
}
export interface SecretSharingProvider {
  NAME: string;
  split: (secret: Uint8Array, k: number, n: number) => Share[];
  combine: (shares: Share[]) => Uint8Array;
}
export { NAME, split, combine, packShare, unpackShare } from './shamir';
