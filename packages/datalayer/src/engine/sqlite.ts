/* ============================================================================
 * sqlite.ts — a thin async wrapper over one wa-sqlite / cr-sqlite connection.
 *
 * Adapted from regina's proven db.ts, but per-INSTANCE (many independent Conns
 * in one process, e.g. several devices in a test) instead of a module global.
 *
 * wa-sqlite's one connection does NOT serialize concurrent async calls, so every
 * touch goes through a single-lane promise queue (`#lock`). cr-sqlite requires
 * crsql_finalize() before close. The VFS is injected at open time: :memory: in
 * Node/tests, the EncryptedIDBVFS in the browser.
 * ==========================================================================*/
import * as SQLite from '@vlcn.io/wa-sqlite';

export type SqlValue = string | number | bigint | Uint8Array | null;
export type Row = Record<string, SqlValue>;

const CHANGE_COLS = '"table","pk","cid","val","col_version","db_version","site_id","cl","seq"';

export class Conn {
  #sqlite3: any;
  #db: number;
  #tail: Promise<unknown> = Promise.resolve();

  constructor(sqlite3: any, db: number) {
    this.#sqlite3 = sqlite3;
    this.#db = db;
  }

  #lock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#tail.then(fn, fn);
    this.#tail = run.then(() => undefined, () => undefined);
    return run;
  }

  async #run(sql: string, params?: SqlValue[]): Promise<void> {
    for await (const stmt of this.#sqlite3.statements(this.#db, sql)) {
      if (params) this.#sqlite3.bind_collection(stmt, params);
      while ((await this.#sqlite3.step(stmt)) === SQLite.SQLITE_ROW) { /* drain */ }
    }
  }
  async #all(sql: string, params?: SqlValue[]): Promise<Row[]> {
    const rows: Row[] = [];
    for await (const stmt of this.#sqlite3.statements(this.#db, sql)) {
      if (params) this.#sqlite3.bind_collection(stmt, params);
      const cols: string[] = this.#sqlite3.column_names(stmt);
      while ((await this.#sqlite3.step(stmt)) === SQLite.SQLITE_ROW) {
        const vals: SqlValue[] = this.#sqlite3.row(stmt);
        const o: Row = {};
        cols.forEach((c, i) => (o[c] = vals[i]));
        rows.push(o);
      }
    }
    return rows;
  }

  /** Execute one or more statements (no params, results drained). */
  exec(sql: string): Promise<void> { return this.#lock(() => this.#sqlite3.exec(this.#db, sql)); }
  /** Execute a parameterized statement. */
  run(sql: string, params?: SqlValue[]): Promise<void> { return this.#lock(() => this.#run(sql, params)); }
  /** Query rows as objects. */
  all<T = Row>(sql: string, params?: SqlValue[]): Promise<T[]> { return this.#lock(() => this.#all(sql, params) as Promise<T[]>); }
  /** First column of the first row, or null. */
  scalar<T extends SqlValue = SqlValue>(sql: string, params?: SqlValue[]): Promise<T | null> {
    return this.#lock(async () => {
      const rows = await this.#all(sql, params);
      if (!rows.length) return null;
      const first = rows[0];
      return (first[Object.keys(first)[0]] as T) ?? null;
    });
  }

  /** Current logical clock — the sync watermark. */
  async dbVersion(): Promise<number> { return Number((await this.scalar('SELECT crsql_db_version()')) ?? 0); }

  /** Export crsql_changes rows with db_version > since as runnable INSERT SQL
   *  (SQLite quote() serializes blobs/ints safely). since=-1 → full state. */
  exportChangesetSQL(since: number): Promise<string> {
    const sql =
      `SELECT 'INSERT INTO crsql_changes(${CHANGE_COLS}) VALUES('||` +
      `quote("table")||','||quote("pk")||','||quote("cid")||','||quote("val")||','||` +
      `quote("col_version")||','||quote("db_version")||','||quote("site_id")||','||` +
      `quote("cl")||','||quote("seq")||');' AS line ` +
      `FROM crsql_changes WHERE db_version > ${Number(since)} ORDER BY db_version, seq`;
    return this.all<{ line: string }>(sql).then((rows) => rows.map((r) => r.line).join('\n'));
  }
  /** Apply a changeset produced by exportChangesetSQL (cr-sqlite merges it). */
  applyChangesetSQL(sql: string): Promise<void> { return sql.trim() ? this.exec(sql) : Promise.resolve(); }

  // NOTE: cr-sqlite's db_version is a LOCAL clock — it is REASSIGNED to the
  // merging replica's clock on apply (only site_id is preserved). So a version
  // vector is NOT portable across replicas; "diff since checkpoint" must be
  // anchored on a LOCAL watermark (this replica's crsql_db_version() captured
  // when it adopted the checkpoint) — see crengine's _wm table.

  async finalize(): Promise<void> {
    await this.#lock(async () => { try { await this.#sqlite3.exec(this.#db, 'SELECT crsql_finalize()'); } catch { /* ignore */ } });
  }
  async close(): Promise<void> {
    await this.finalize();
    await this.#lock(() => this.#sqlite3.close(this.#db));
  }
}

/** Bootstrap a cr-sqlite module from a wasm binary, then open connections on it.
 *  One module can back many connections (each open_v2 is independent). */
export const createEngine = async (wasmBinary: ArrayBuffer): Promise<{
  openMemory: () => Promise<Conn>;
  openVFS: (path: string, vfs: { name: string }, register: (s: any) => void) => Promise<Conn>;
  sqlite3: any;
}> => {
  const SQLiteFactory = (await import('@vlcn.io/wa-sqlite/dist/crsqlite.mjs')).default;
  const module = await SQLiteFactory({ wasmBinary });
  const sqlite3 = SQLite.Factory(module);
  return {
    sqlite3,
    openMemory: async () => new Conn(sqlite3, await sqlite3.open_v2(':memory:')),
    openVFS: async (path, vfs, register) => {
      register(sqlite3);
      return new Conn(sqlite3, await sqlite3.open_v2(path, undefined, vfs.name));
    },
  };
};
