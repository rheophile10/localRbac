import { describe, it, expect } from 'vitest';
import * as C from '../src/crypto';

// all k-sized subsets of arr
const combos = <T>(arr: T[], k: number): T[][] => {
  if (k === 0) return [[]];
  if (k > arr.length) return [];
  const [head, ...rest] = arr;
  return [...combos(rest, k - 1).map((c) => [head, ...c]), ...combos(rest, k)];
};

describe('Shamir secret sharing over GF(256)', () => {
  it('any k shares reconstruct the secret; any fewer do not', () => {
    const secret = C.randomKey(); // 32-byte data-key
    const shares = C.splitSecret(secret, 3, 5);
    expect(shares).toHaveLength(5);

    for (const sub of combos(shares, 3)) expect(C.combineShares(sub)).toEqual(secret);
    expect(C.combineShares(shares)).toEqual(secret); // all 5 also works
    for (const sub of combos(shares, 2)) expect(C.combineShares(sub)).not.toEqual(secret);
  });

  it('k=1 is trivial; k=n requires every share', () => {
    const s = C.randomKey();
    expect(C.combineShares(C.splitSecret(s, 1, 3).slice(0, 1))).toEqual(s);
    const all = C.splitSecret(s, 3, 3);
    expect(C.combineShares(all)).toEqual(s);
    expect(C.combineShares(all.slice(0, 2))).not.toEqual(s);
  });

  it('rejects bad parameters and malformed shares', () => {
    expect(() => C.splitSecret(C.randomKey(), 4, 3)).toThrow(); // k > n
    expect(() => C.splitSecret(new Uint8Array(0), 2, 3)).toThrow(); // empty secret
    const shares = C.splitSecret(C.randomKey(), 2, 3);
    expect(() => C.combineShares([shares[0], shares[0]])).toThrow(); // duplicate x
  });

  it('shares pack/unpack round-trip for transport', () => {
    const shares = C.splitSecret(C.randomKey(), 2, 3);
    for (const s of shares) {
      const round = C.unpackShare(C.packShare(s));
      expect(round.x).toBe(s.x);
      expect(round.y).toEqual(s.y);
    }
  });
});
