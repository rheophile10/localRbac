// Encoding/byte helpers shared by every crypto domain. No protocol here.
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (s: string): Uint8Array => encoder.encode(s);
export const fromUtf8 = (b: Uint8Array): string => decoder.decode(b);
export const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const fromHex = (h: string): Uint8Array => {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
};
export const short = (h: string): string => h.slice(0, 8);
export const randomBytes = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
export const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const o = new Uint8Array(a.length + b.length);
  o.set(a);
  o.set(b, a.length);
  return o;
};
