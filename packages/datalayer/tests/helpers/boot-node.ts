// Node-only bootstrap: load the cr-sqlite wasm from disk. Both main and staging
// connections use :memory: (the encrypting IndexedDB VFS is browser-only; the
// engine logic is identical). Browser code uses bootBrowserEngine instead.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createEngine } from '../../src/engine/sqlite';
import type { CrEngine } from '../../src/engine/crengine';

// low-level engine (openMemory/openVFS) — used by the spine test
export const bootNodeEngine = () => {
  const require = createRequire(import.meta.url);
  const wasm = readFileSync(require.resolve('@vlcn.io/wa-sqlite/dist/crsqlite.wasm'));
  return createEngine(wasm.buffer as ArrayBuffer);
};

// CrEngine adapter for the compartmented-RBAC engine tests
export const nodeCrEngine = async (): Promise<CrEngine> => {
  const base = await bootNodeEngine();
  return { openMain: () => base.openMemory(), openStaging: () => base.openMemory() };
};
