// Types for the vendored EncryptedIDBVFS.js (a wa-sqlite VFS with transparent
// per-block page encryption over IndexedDB).
export class EncryptedIDBVFS {
  /** @param idbDatabaseName IndexedDB database name
   *  @param key 32-byte page-encryption key, or null to disable encryption */
  constructor(idbDatabaseName?: string, key?: Uint8Array | null, options?: object);
  name: string; // registration name; may be reassigned before vfs_register
  close(): Promise<void>;
}
