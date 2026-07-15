/* Spike: prove @vlcn.io/crsqlite-wasm (cr-sqlite CRDT extension) runs on a custom
 * IndexedDB VFS — CRR tables, crsql_changes, and persistence across reopen.
 * Runs on the Vite dev server (http); the engine mechanics are identical on
 * file:// once the wasm is inlined (already proven for sql.js). */
// @ts-expect-error — crsqlite.mjs has no types
import SQLiteFactory from '@vlcn.io/wa-sqlite/dist/crsqlite.mjs';
// @ts-expect-error — no types
import * as SQLite from '@vlcn.io/wa-sqlite';
// @ts-expect-error — example module, no types
import { IDBBatchAtomicVFS } from '@vlcn.io/wa-sqlite/src/examples/IDBBatchAtomicVFS.js';
import wasmUrl from '@vlcn.io/wa-sqlite/dist/crsqlite.wasm?url';

const out = document.querySelector('#out') as HTMLElement;
const lines: string[] = [];
const log = (m: string): void => { lines.push(m); out.textContent = lines.join('\n'); };

const IDB_NAME = 'spike-idb';

// open a cr-sqlite connection on the IndexedDB VFS
const openDb = async (): Promise<{ sqlite3: any; db: number; vfs: any }> => {
  const wasmBinary = await (await fetch(wasmUrl)).arrayBuffer();
  const module = await SQLiteFactory({ wasmBinary });
  const sqlite3 = SQLite.Factory(module);
  const vfs = new IDBBatchAtomicVFS(IDB_NAME);
  sqlite3.vfs_register(vfs, true); // makeDefault
  const db = await sqlite3.open_v2('/spike.db', undefined, IDB_NAME);
  return { sqlite3, db, vfs };
};

const all = async (sqlite3: any, db: number, sql: string): Promise<unknown[][]> => {
  const rows: unknown[][] = [];
  await sqlite3.exec(db, sql, (row: unknown[]) => { rows.push(row.slice()); });
  return rows;
};

const run = async (): Promise<void> => {
  try {
    // fresh start
    await new Promise<void>((res) => { const r = indexedDB.deleteDatabase(IDB_NAME); r.onsuccess = () => res(); r.onerror = () => res(); r.onblocked = () => res(); });

    // ---- session 1: create a CRR table, insert, read changes ----
    let s = await openDb();
    log('crsqlite booted on IndexedDB VFS ✓');
    const ver = await all(s.sqlite3, s.db, 'SELECT crsql_db_version()');
    log('crsql_db_version() = ' + JSON.stringify(ver[0]?.[0]));
    await s.sqlite3.exec(s.db, 'CREATE TABLE foo(id INTEGER NOT NULL PRIMARY KEY, val TEXT)');
    await s.sqlite3.exec(s.db, "SELECT crsql_as_crr('foo')");
    log('created CRR table foo ✓');
    await s.sqlite3.exec(s.db, "INSERT INTO foo VALUES (1,'alpha'),(2,'bravo')");
    const changes = await all(s.sqlite3, s.db, 'SELECT count(*) FROM crsql_changes');
    log('crsql_changes rows after 2 inserts = ' + JSON.stringify(changes[0]?.[0]));
    await s.sqlite3.exec(s.db, "SELECT crsql_finalize()");
    await s.sqlite3.close(s.db);
    await s.vfs.close();
    log('session 1 closed (finalized) ✓');

    // ---- session 2: reopen a NEW connection on the SAME IndexedDB → data persists ----
    s = await openDb();
    const persisted = await all(s.sqlite3, s.db, 'SELECT id,val FROM foo ORDER BY id');
    log('after reopen, foo = ' + JSON.stringify(persisted));
    const ok = persisted.length === 2 && persisted[0][1] === 'alpha' && persisted[1][1] === 'bravo';
    await s.sqlite3.exec(s.db, "SELECT crsql_finalize()");
    await s.sqlite3.close(s.db);
    await s.vfs.close();

    log(ok ? 'RESULT: PASS — CRDT engine persists across reopen on the IndexedDB VFS' : 'RESULT: FAIL — data did not persist');
  } catch (e) {
    log('RESULT: FAIL — ' + ((e as Error).stack || (e as Error).message));
  }
};

void run();
