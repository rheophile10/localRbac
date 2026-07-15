// Shamir Secret Sharing over GF(2^8) — the one hand-rolled primitive (no Web
// Crypto / noble equivalent exists). It is NOT a cipher: it only splits a
// random data-key into k-of-n shares. Confidentiality still rests on the AEAD
// that the data-key encrypts. Byte-wise independent degree-(k-1) polynomials;
// Lagrange interpolation at x=0 to reconstruct. (AES reduction poly 0x11b.)
import { randomBytes } from '../util';

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    const hi = x & 0x80;
    x = (x << 1) & 0xff;
    if (hi) x ^= 0x1b;
    x ^= EXP[i]; // *2 (reduced) XOR self == *3 (generator)
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

const mul = (a: number, b: number): number => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
const div = (a: number, b: number): number => {
  if (b === 0) throw new Error('division by zero in GF(256)');
  return a === 0 ? 0 : EXP[LOG[a] + 255 - LOG[b]];
};

export interface Share {
  x: number; // evaluation point 1..n (never 0)
  y: Uint8Array; // one field element per secret byte
}

export const NAME = 'shamir-gf256';

export const split = (secret: Uint8Array, k: number, n: number): Share[] => {
  if (k < 1 || k > n) throw new Error('require 1 <= k <= n');
  if (n > 255) throw new Error('n must be <= 255');
  if (secret.length === 0) throw new Error('empty secret');
  const len = secret.length;
  const rnd = randomBytes((k - 1) * len); // coefficients, row-major by degree
  const shares: Share[] = [];
  for (let i = 0; i < n; i++) {
    const x = i + 1;
    const y = new Uint8Array(len);
    for (let b = 0; b < len; b++) {
      let acc = secret[b]; // constant term = secret byte
      let xp = 1;
      for (let d = 1; d < k; d++) {
        xp = mul(xp, x); // x^d
        acc ^= mul(rnd[(d - 1) * len + b], xp);
      }
      y[b] = acc;
    }
    shares.push({ x, y });
  }
  return shares;
};

export const combine = (shares: Share[]): Uint8Array => {
  if (shares.length === 0) throw new Error('no shares');
  const len = shares[0].y.length;
  const xs = new Set<number>();
  for (const s of shares) {
    if (s.x === 0) throw new Error('invalid share x=0');
    if (s.y.length !== len) throw new Error('share length mismatch');
    if (xs.has(s.x)) throw new Error('duplicate share x');
    xs.add(s.x);
  }
  const out = new Uint8Array(len);
  for (let b = 0; b < len; b++) {
    let acc = 0;
    for (let j = 0; j < shares.length; j++) {
      const xj = shares[j].x;
      let num = 1;
      let den = 1;
      for (let m = 0; m < shares.length; m++) {
        if (m === j) continue;
        const xm = shares[m].x;
        num = mul(num, xm); // (0 - xm) == xm  (subtraction is XOR)
        den = mul(den, xj ^ xm); // (xj - xm) == xj ^ xm
      }
      acc ^= mul(shares[j].y[b], div(num, den));
    }
    out[b] = acc;
  }
  return out;
};

// Wire format for a share: [x][y...]  (transport / sealing to a custodian key).
export const packShare = (s: Share): Uint8Array => {
  const out = new Uint8Array(1 + s.y.length);
  out[0] = s.x;
  out.set(s.y, 1);
  return out;
};
export const unpackShare = (bytes: Uint8Array): Share => ({ x: bytes[0], y: bytes.slice(1) });
