/* Spike 2: prove the ENCRYPTING VFS. cr-sqlite on EncryptedIDBVFS with a page
 * key: data round-trips with the right key, IndexedDB holds only ciphertext
 * (a plaintext marker is NOT findable in the raw blocks), and a wrong key
 * fails to read. Runs self-contained on file://. */
// @ts-expect-error — crsqlite.mjs has no types
import SQLiteFactory from '@vlcn.io/wa-sqlite/dist/crsqlite.mjs';
// @ts-expect-error — no types
import * as SQLite from '@vlcn.io/wa-sqlite';
import { EncryptedIDBVFS } from '../../datalayer/src/engine/EncryptedIDBVFS.js';
import wasmUrl from '@vlcn.io/wa-sqlite/dist/crsqlite.wasm?url';

const out = document.querySelector('#out') as HTMLElement;
const lines: string[] = [];
const log = (m: string): void => { lines.push(m); out.textContent = lines.join('\n'); };

const IDB = 'spike2-idb';
const MARKER = 'SECRETMARKER_huntertwo'; // plaintext we look for at rest
const KEY_A = new Uint8Array(32).fill(7);
const KEY_B = new Uint8Array(32).fill(9); // wrong key

let sqlModule: unknown;
let regCounter = 0;
const openDb = async (key: Uint8Array): Promise<{ sqlite3: any; db: number; vfs: any }> => {
  if (!sqlModule) sqlModule = await SQLiteFactory({ wasmBinary: await (await fetch(wasmUrl)).arrayBuffer() });
  const sqlite3 = SQLite.Factory(sqlModule);
  const vfs = new EncryptedIDBVFS(IDB, key); // IDB storage name is constant
  vfs.name = 'encvfs-' + regCounter++;        // unique REGISTRATION name per open
  sqlite3.vfs_register(vfs, true);
  const db = await sqlite3.open_v2('/enc.db', undefined, vfs.name);
  return { sqlite3, db, vfs };
};
const all = async (sqlite3: any, db: number, sql: string): Promise<unknown[][]> => {
  const rows: unknown[][] = [];
  await sqlite3.exec(db, sql, (r: unknown[]) => rows.push(r.slice()));
  return rows;
};
const closeDb = async (s: { sqlite3: any; db: number; vfs: any }): Promise<void> => {
  await s.sqlite3.exec(s.db, 'SELECT crsql_finalize()');
  await s.sqlite3.close(s.db);
  await s.vfs.close();
};

// read the raw IndexedDB 'blocks' store and scan every record for the marker /
// encryption flag — bypasses our VFS entirely, so it sees what's truly at rest
const rawScan = (): Promise<{ total: number; encrypted: number; markerFound: boolean }> =>
  new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction('blocks', 'readonly');
      const cur = tx.objectStore('blocks').openCursor();
      let total = 0, encrypted = 0, markerFound = false;
      const needle = new TextEncoder().encode(MARKER);
      const contains = (hay: Uint8Array, n: Uint8Array): boolean => {
        outer: for (let i = 0; i + n.length <= hay.length; i++) { for (let j = 0; j < n.length; j++) if (hay[i + j] !== n[j]) continue outer; return true; }
        return false;
      };
      cur.onsuccess = () => {
        const c = cur.result;
        if (!c) { db.close(); resolve({ total, encrypted, markerFound }); return; }
        const v = c.value as { data?: unknown; _e?: number };
        total++;
        if (v._e === 1) encrypted++;
        if (v.data instanceof Uint8Array && contains(v.data, needle)) markerFound = true;
        c.continue();
      };
      cur.onerror = () => reject(cur.error);
    };
  });

const run = async (): Promise<void> => {
  try {
    await new Promise<void>((res) => { const r = indexedDB.deleteDatabase(IDB); r.onsuccess = () => res(); r.onerror = () => res(); r.onblocked = () => res(); });

    // write with KEY_A
    let s = await openDb(KEY_A);
    await s.sqlite3.exec(s.db, 'CREATE TABLE t(id INTEGER NOT NULL PRIMARY KEY, note TEXT)');
    await s.sqlite3.exec(s.db, "SELECT crsql_as_crr('t')");
    await s.sqlite3.exec(s.db, `INSERT INTO t VALUES (1, '${MARKER}')`);
    await closeDb(s);
    log('wrote a CRR row with an encrypting VFS ✓');

    // at-rest inspection: raw IndexedDB should hold ciphertext only
    const scan = await rawScan();
    log(`raw IndexedDB: ${scan.total} blocks, ${scan.encrypted} encrypted, plaintext marker present = ${scan.markerFound}`);
    const atRestOk = scan.encrypted > 0 && !scan.markerFound;
    log(atRestOk ? 'AT-REST: ciphertext only — marker NOT found ✓' : 'AT-REST: FAIL — plaintext leaked');

    // reopen with the RIGHT key → decrypts
    s = await openDb(KEY_A);
    const good = await all(s.sqlite3, s.db, 'SELECT note FROM t WHERE id=1');
    await closeDb(s);
    const rightKeyOk = good[0]?.[0] === MARKER;
    log(`reopen with correct key → note = ${JSON.stringify(good[0]?.[0])} ${rightKeyOk ? '✓' : '✗'}`);

    // reopen with the WRONG key → must fail (auth tag)
    let wrongKeyFailed = false;
    try {
      const w = await openDb(KEY_B);
      await all(w.sqlite3, w.db, 'SELECT note FROM t WHERE id=1');
      await closeDb(w);
    } catch { wrongKeyFailed = true; }
    log(`reopen with WRONG key → ${wrongKeyFailed ? 'failed to open/read ✓' : 'UNEXPECTEDLY SUCCEEDED ✗'}`);

    log((atRestOk && rightKeyOk && wrongKeyFailed) ? 'RESULT: PASS — encrypting VFS works (ciphertext at rest, key-gated)' : 'RESULT: FAIL');
  } catch (e) {
    log('RESULT: FAIL — ' + ((e as Error).stack || (e as Error).message));
  }
};

void run();
