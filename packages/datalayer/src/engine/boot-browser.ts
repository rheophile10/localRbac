/* Browser bootstrap: build a CrEngine whose MAIN connection persists to an
 * encrypted IndexedDB (via EncryptedIDBVFS, keyed to the session) and whose
 * STAGING connection is a throwaway :memory: db. The caller passes the crsqlite
 * wasm binary (inlined as a data: URI by the app build, so no network fetch —
 * works on file://). */
import { createEngine, type Conn } from './sqlite';
import type { CrEngine } from './crengine';
import { EncryptedIDBVFS } from './EncryptedIDBVFS.js';

export interface BrowserEngineOptions {
  wasmBinary: ArrayBuffer;
  /** IndexedDB database name for this instance's persistent store. */
  idbName: string;
}

export const bootBrowserEngine = async (opts: BrowserEngineOptions): Promise<CrEngine> => {
  const base = await createEngine(opts.wasmBinary);
  let regCount = 0;
  return {
    openMain: (key: Uint8Array | null): Promise<Conn> => {
      const vfs = new EncryptedIDBVFS(opts.idbName, key) as { name: string };
      vfs.name = `encvfs-${opts.idbName}-${regCount++}`; // unique registration per open
      return base.openVFS(`/${opts.idbName}.db`, vfs, (s: unknown) => (s as { vfs_register: (v: unknown, d: boolean) => void }).vfs_register(vfs, false));
    },
    openStaging: (): Promise<Conn> => base.openMemory(),
  };
};
