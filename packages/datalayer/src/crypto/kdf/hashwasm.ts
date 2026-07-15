// Password key-derivation — hash-wasm Argon2id (WASM, memory-hard).
// Async because a >4 KB WASM module cannot be compiled synchronously on the
// main thread. Parameters are a PROTOCOL CONSTANT: every participant must use
// the identical values or the same credentials derive different keys.
import { argon2id } from 'hash-wasm';

export const NAME = 'hash-wasm/argon2id';
const PARAMS = { parallelism: 1, iterations: 3, memorySize: 65536 /* KiB = 64 MiB */ } as const;

export const deriveKey = async (password: Uint8Array, salt: Uint8Array, dkLen: number): Promise<Uint8Array> =>
  (await argon2id({ password, salt, ...PARAMS, hashLength: dkLen, outputType: 'binary' })) as Uint8Array;
