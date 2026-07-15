/* ============================================================================
 * crengine.ts — compartmented-RBAC engine on cr-sqlite (async).
 *
 * cr-sqlite provides the CRDT (per-column LWW convergence + crsql_changes as the
 * sync transport). We layer RBAC on top:
 *   - every data/system row carries an embedded `author` (Ed25519 pubkey) and
 *     `sig` — so authenticity travels with the row through any relay, unlike a
 *     sender-level changeset signature (cr-sqlite changes keep their origin
 *     site_id and gossip transitively).
 *   - a cell value is encrypted under ONE resource's data-key (DEK); a record
 *     tagged to N resources has up to N cell rows (multiple ciphertexts).
 *   - IMPORT authorizes: apply the incoming changeset to a throwaway STAGING
 *     connection (rows become readable — our TEXT pk encodes rid|resource|col),
 *     verify each row's sig + writer/admin grant, and only merge into main if
 *     all pass. Reads decrypt only the resources the viewer holds a DEK for and
 *     LWW-merge across them (compartment fold).
 *
 * 'notes' is the default resource, so single-compartment use is unchanged.
 * ==========================================================================*/
import type { Conn, SqlValue } from './sqlite';
import * as C from '../crypto';
import * as compartment from '../compartment';
import * as consensus from '../consensus';
import type { ConsolidatedRecord } from '../ceremony';
import type { Identity, Role } from '../types';

const SEP = '\x1f';
const DEFAULT = 'notes';
const j = (...parts: (string | number)[]): string => parts.join(SEP);

export interface CrEngine {
  // main DB: encrypted IndexedDB in the browser (keyed to the session), or
  // :memory: in Node/tests. staging: always a throwaway :memory: conn.
  openMain: (key: Uint8Array | null) => Promise<Conn>;
  openStaging: () => Promise<Conn>;
}

export interface ImportResult { applied: boolean; rejected: string[]; stateRoot: string; }
export type CrDevice = ReturnType<typeof createCrDevice>;

const SCHEMA = `
  CREATE TABLE adminroot(k TEXT NOT NULL PRIMARY KEY, pub TEXT);
  CREATE TABLE dekver(pk TEXT NOT NULL PRIMARY KEY, resource TEXT, ver INTEGER, author TEXT, sig TEXT);
  CREATE TABLE identity(pub TEXT NOT NULL PRIMARY KEY, name TEXT, xpub TEXT, author TEXT, sig TEXT);
  CREATE TABLE grantrec(pk TEXT NOT NULL PRIMARY KEY, subject TEXT, resource TEXT, role TEXT, revoked INTEGER, epoch INTEGER, author TEXT, sig TEXT);
  CREATE TABLE keywrap(pk TEXT NOT NULL PRIMARY KEY, subject TEXT, resource TEXT, dek_ver INTEGER, box TEXT, author TEXT, sig TEXT);
  CREATE TABLE cell(pk TEXT NOT NULL PRIMARY KEY, rid TEXT, resource TEXT, col TEXT, ct TEXT, dek_ver INTEGER, author TEXT, sig TEXT);
  CREATE TABLE archived(rid TEXT NOT NULL PRIMARY KEY, flag INTEGER, author TEXT, sig TEXT);
  CREATE TABLE checkpoint(hash TEXT NOT NULL PRIMARY KEY, epoch INTEGER, parent TEXT, members TEXT, author TEXT, sig TEXT);
  CREATE TABLE _wm(hash TEXT NOT NULL PRIMARY KEY, dbv INTEGER); -- LOCAL, not a CRR: our db_version when we adopted a checkpoint
  SELECT crsql_as_crr('adminroot');
  SELECT crsql_as_crr('dekver');
  SELECT crsql_as_crr('identity');
  SELECT crsql_as_crr('grantrec');
  SELECT crsql_as_crr('keywrap');
  SELECT crsql_as_crr('cell');
  SELECT crsql_as_crr('archived');
  SELECT crsql_as_crr('checkpoint');
`;

// ---- canonical bytes each row's signature covers -------------------------
const sigInput = {
  identity: (r: { pub: string; name: string; xpub: string }) => j('identity', r.pub, r.name, r.xpub),
  dekver: (r: { resource: string; ver: number }) => j('dekver', r.resource, r.ver),
  grantrec: (r: { subject: string; resource: string; role: string; revoked: number; epoch: number }) => j('grant', r.subject, r.resource, r.role, r.revoked, r.epoch),
  keywrap: (r: { subject: string; resource: string; dek_ver: number; box: string }) => j('keywrap', r.subject, r.resource, r.dek_ver, r.box),
  cell: (r: { pk: string; ct: string; dek_ver: number }) => j('cell', r.pk, r.ct, r.dek_ver),
  archived: (r: { rid: string; flag: number }) => j('archived', r.rid, r.flag),
  checkpoint: (r: { hash: string; epoch: number; parent: string; members: string }) => j('checkpoint', r.hash, r.epoch, r.parent, r.members),
};

// A signed identity card — a user's public identity, shared out-of-band so an
// admin can grant to their key without ever seeing private material.
export interface IdentityCard { pub: string; name: string; xpub: string; sig: string; }

export const createCrDevice = (engine: CrEngine, label: string) => {
  const state: { conn: Conn | null; session: Identity | null } = { conn: null, session: null };
  const dekCache = new Map<string, Uint8Array | null>();

  const conn = (): Conn => { if (!state.conn) throw new Error('no database'); return state.conn; };
  const session = (): Identity => { if (!state.session) throw new Error('not logged in'); return state.session; };
  const sign = (msg: string): Promise<string> => C.signMessage(msg, session().edPriv);
  // at-rest key for the encrypting VFS, derived from the logged-in identity
  const vfsKey = (): Promise<Uint8Array | null> => (state.session ? C.deriveVaultKey(state.session.edPriv) : Promise.resolve(null));

  const adminPub = async (): Promise<string | null> => (state.conn ? ((await conn().scalar<string>("SELECT pub FROM adminroot WHERE k='root'")) ?? null) : null);
  const isAdmin = async (): Promise<boolean> => !!state.session && state.session.edPub === (await adminPub());

  const dekVerFor = async (resource: string): Promise<number> =>
    Number((await conn().scalar<number>('SELECT ver FROM dekver WHERE resource=? ORDER BY ver DESC LIMIT 1', [resource])) ?? 0);

  /* ---- writes (local user trusted locally; security is enforced at import) */
  const putIdentity = async (id: Identity): Promise<void> => {
    const row = { pub: id.edPub, name: id.name, xpub: id.xPub };
    const sig = await sign(sigInput.identity(row));
    await conn().run('INSERT OR REPLACE INTO identity(pub,name,xpub,author,sig) VALUES(?,?,?,?,?)',
      [row.pub, row.name, row.xpub, session().edPub, sig]);
  };
  const putDekver = async (resource: string, ver: number): Promise<void> => {
    const row = { resource, ver };
    const sig = await sign(sigInput.dekver(row));
    await conn().run('INSERT OR REPLACE INTO dekver(pk,resource,ver,author,sig) VALUES(?,?,?,?,?)',
      [j(resource, ver), resource, ver, session().edPub, sig]);
  };
  const putGrant = async (subject: string, resource: string, role: Role, revoked: boolean, epoch: number): Promise<void> => {
    const row = { subject, resource, role, revoked: revoked ? 1 : 0, epoch };
    const sig = await sign(sigInput.grantrec(row));
    await conn().run('INSERT OR REPLACE INTO grantrec(pk,subject,resource,role,revoked,epoch,author,sig) VALUES(?,?,?,?,?,?,?,?)',
      [j(subject, resource), subject, resource, role, row.revoked, epoch, session().edPub, sig]);
  };
  const putKeywrap = async (subject: string, resource: string, ver: number, box: string): Promise<void> => {
    const row = { subject, resource, dek_ver: ver, box };
    const sig = await sign(sigInput.keywrap(row));
    await conn().run('INSERT OR REPLACE INTO keywrap(pk,subject,resource,dek_ver,box,author,sig) VALUES(?,?,?,?,?,?,?)',
      [j(subject, resource, ver), subject, resource, ver, box, session().edPub, sig]);
  };
  const putCell = async (rid: string, resource: string, col: string, ct: string, ver: number): Promise<void> => {
    const pk = j(rid, resource, col);
    const row = { pk, ct, dek_ver: ver };
    const sig = await sign(sigInput.cell(row));
    await conn().run('INSERT OR REPLACE INTO cell(pk,rid,resource,col,ct,dek_ver,author,sig) VALUES(?,?,?,?,?,?,?,?)',
      [pk, rid, resource, col, ct, ver, session().edPub, sig]);
  };
  const putArchived = async (rid: string, flag: boolean): Promise<void> => {
    const row = { rid, flag: flag ? 1 : 0 };
    const sig = await sign(sigInput.archived(row));
    await conn().run('INSERT OR REPLACE INTO archived(rid,flag,author,sig) VALUES(?,?,?,?)',
      [rid, row.flag, session().edPub, sig]);
  };

  /* ---- DEK access --------------------------------------------------------*/
  const getDEK = async (resource: string, ver: number): Promise<Uint8Array | null> => {
    if (!state.session) return null;
    const ck = j(state.session.edPub, resource, ver);
    if (dekCache.has(ck)) return dekCache.get(ck) ?? null;
    let dek: Uint8Array | null = null;
    if (state.session.edPub === (await adminPub())) {
      dek = await C.deriveResourceDEK(state.session.edPriv, resource, ver);
    } else {
      const box = await conn().scalar<string>('SELECT box FROM keywrap WHERE subject=? AND resource=? AND dek_ver=?', [state.session.edPub, resource, ver]);
      if (box) { try { dek = await C.unseal(state.session.xPriv, state.session.xPub, box); } catch { dek = null; } }
    }
    dekCache.set(ck, dek);
    return dek;
  };

  /* ---- authorization -----------------------------------------------------
   * writerIn checks a specific connection's grant state. Local write-gating uses
   * MAIN; import authorization uses STAGING (whose grant rows are verified
   * admin-signed first, so its derived grant state is trustworthy). */
  const writerIn = async (c: Conn, admin: string | null, author: string, resource: string): Promise<boolean> => {
    if (author === admin) return true;
    const g = await c.all<{ role: string; revoked: number }>('SELECT role,revoked FROM grantrec WHERE subject=? AND resource=?', [author, resource]);
    return g.length > 0 && g[0].role === 'writer' && g[0].revoked === 0;
  };
  const writerOf = async (author: string, resource: string): Promise<boolean> => writerIn(conn(), await adminPub(), author, resource);

  /* ---- session -----------------------------------------------------------
   * Identity is EITHER freshly generated (register a new identity — then export
   * a keystore file to keep it) OR loaded from an uploaded keystore file. The
   * keystore is never stored by the app; the user holds the file. Keys are not
   * derived from the passphrase — the passphrase only wraps the keystore. */
  const login = async (name: string): Promise<Identity> => { // generate a fresh identity
    state.session = await C.createIdentity(name);
    dekCache.clear();
    return state.session;
  };
  const unlock = async (blob: C.KeystoreBlob, passphrase: string): Promise<Identity> => { // load from a keystore file
    state.session = await C.loadKeystore(blob, passphrase); // throws on wrong passphrase
    dekCache.clear();
    return state.session;
  };
  // Wrap the current identity as a downloadable keystore file (new salt/IV each
  // call, so this doubles as passphrase migration → a fresh file, same identity).
  const exportKeystore = (passphrase: string): Promise<C.KeystoreBlob> => C.createKeystore(session(), passphrase);
  const logout = (): void => { state.session = null; dekCache.clear(); };

  // A user's public identity card, self-signed — shared so an admin can grant
  // to their key. The card's signature IS the identity row's signature, so an
  // admin can store it verbatim (author == the card owner).
  const exportIdentityCard = async (): Promise<IdentityCard> => {
    const s = session();
    const row = { pub: s.edPub, name: s.name, xpub: s.xPub };
    return { ...row, sig: await sign(sigInput.identity(row)) };
  };

  const initSchema = async (c: Conn): Promise<void> => { await c.exec(SCHEMA); };

  const genesis = async (): Promise<void> => {
    const s = session();
    state.conn = await engine.openMain(await vfsKey());
    await initSchema(state.conn);
    await conn().run("INSERT OR REPLACE INTO adminroot(k,pub) VALUES('root',?)", [s.edPub]);
    await putIdentity(s);
    await putDekver(DEFAULT, 1);
    dekCache.clear();
  };

  /* ---- admin ops ---------------------------------------------------------*/
  const knownUsers = async (): Promise<Array<{ pub: string; name: string; xpub: string; role: Role }>> => {
    const rows = await conn().all<{ pub: string; name: string; xpub: string; role: string | null; revoked: number | null }>(
      `SELECT i.pub,i.name,i.xpub,g.role,g.revoked FROM identity i
       LEFT JOIN grantrec g ON g.subject=i.pub AND g.resource='notes'`);
    return rows.map((r) => ({ pub: r.pub, name: r.name, xpub: r.xpub, role: (r.revoked ? 'none' : (r.role as Role) || 'none') as Role }));
  };

  const ensureDekVer = async (resource: string): Promise<number> => {
    let v = await dekVerFor(resource);
    if (v === 0) { await putDekver(resource, 1); v = 1; }
    return v;
  };
  const wrapDekTo = async (subjectPub: string, resource: string, ver: number): Promise<void> => {
    const xpub = await conn().scalar<string>('SELECT xpub FROM identity WHERE pub=?', [subjectPub]);
    if (!xpub) throw new Error('unknown identity (import their card first)');
    const dek = await C.deriveResourceDEK(session().edPriv, resource, ver); // admin derives
    await putKeywrap(subjectPub, resource, ver, await C.sealTo(xpub, dek));
  };
  // current reader/writer subjects on a resource (per-resource, not notes-scoped)
  const membersOf = async (resource: string): Promise<string[]> =>
    (await conn().all<{ subject: string }>("SELECT subject FROM grantrec WHERE resource=? AND revoked=0 AND role IN ('reader','writer')", [resource])).map((r) => r.subject);

  // Bump a resource's DEK version and re-seal the new key to its current members
  // (except `exclude`). The shared rotation primitive. Returns the new version.
  const rotateResource = async (resource: string, exclude?: string): Promise<number> => {
    const nv = (await dekVerFor(resource)) + 1;
    await putDekver(resource, nv);
    const admin = await adminPub();
    for (const pub of await membersOf(resource)) {
      if (pub === exclude || pub === admin) continue;
      await wrapDekTo(pub, resource, nv);
    }
    dekCache.clear();
    return nv;
  };

  const grant = async (subjectPub: string, role: 'reader' | 'writer', resource = DEFAULT): Promise<void> => {
    if (!(await isAdmin())) throw new Error('admin only');
    const cur = await ensureDekVer(resource);
    await putGrant(subjectPub, resource, role, false, cur);
    await wrapDekTo(subjectPub, resource, cur);
  };

  // Revoke a grant. DEK rotation is OPTIONAL: with rotate=true (default, the
  // secure choice) the revoked user is locked out of FUTURE writes immediately;
  // with rotate=false they keep the current key until a later consensus rotation.
  const revoke = async (subjectPub: string, resource = DEFAULT, rotate = true): Promise<void> => {
    if (!(await isAdmin())) throw new Error('admin only');
    await putGrant(subjectPub, resource, 'none', true, await dekVerFor(resource));
    if (rotate) await rotateResource(resource, subjectPub); // revoked user already excluded (grant now revoked)
    else dekCache.clear();
  };

  // Rotate one resource's DEK (a standalone admin action, e.g. at a consensus event).
  const rotateDek = async (resource = DEFAULT): Promise<number> => {
    if (!(await isAdmin())) throw new Error('admin only');
    return rotateResource(resource);
  };
  // Rotate every resource's DEK — the "rotate at lock" option for the ceremony.
  const rotateAllDeks = async (): Promise<void> => {
    if (!(await isAdmin())) throw new Error('admin only');
    for (const { resource } of await conn().all<{ resource: string }>('SELECT DISTINCT resource FROM dekver')) {
      await rotateResource(resource);
    }
  };
  // Admin imports a user's self-signed identity card (verify its signature, then
  // store the identity row verbatim with author == the card owner). After this,
  // grant() can seal keywraps to their xpub.
  const importIdentityCard = async (card: IdentityCard): Promise<void> => {
    if (!(await isAdmin())) throw new Error('admin only');
    if (!(await C.verifyMessage(sigInput.identity({ pub: card.pub, name: card.name, xpub: card.xpub }), card.sig, card.pub)))
      throw new Error('invalid identity card signature');
    await conn().run('INSERT OR REPLACE INTO identity(pub,name,xpub,author,sig) VALUES(?,?,?,?,?)',
      [card.pub, card.name, card.xpub, card.pub, card.sig]);
  };

  /* ---- note ops ----------------------------------------------------------*/
  const denied = (m: string): never => { const e = new Error(m) as Error & { denied?: boolean }; e.denied = true; throw e; };
  const writeCell = async (rid: string, col: string, plaintext: string, resource = DEFAULT): Promise<void> => {
    if (!(await writerOf(session().edPub, resource))) denied(`DENIED: no write permission on ${resource}`);
    const ver = await ensureDekVer(resource);
    const dek = await getDEK(resource, ver);
    if (!dek) throw new Error('no data-key to encrypt with');
    await putCell(rid, resource, col, await C.aeadEncrypt(dek, plaintext), ver);
  };
  const addNote = async (title: string, body: string, resource = DEFAULT): Promise<string> => {
    const id = crypto.randomUUID();
    await writeCell(id, 'title', title, resource);
    await writeCell(id, 'body', body, resource);
    return id;
  };
  const archiveRecord = async (rid: string, flag = true): Promise<void> => {
    // writer on any resource the record is in
    const resources = (await conn().all<{ resource: string }>('SELECT DISTINCT resource FROM cell WHERE rid=?', [rid])).map((r) => r.resource);
    let ok = false;
    for (const r of resources) if (await writerOf(session().edPub, r)) { ok = true; break; }
    if (!ok) denied('DENIED: no write permission');
    await putArchived(rid, flag);
  };

  /* ---- reads (compartment fold over decryptable resources) ---------------*/
  const decryptedCells = async (): Promise<compartment.DecryptedCell[]> => {
    const rows = await conn().all<{ rid: string; resource: string; col: string; ct: string; dek_ver: number }>(
      'SELECT rid,resource,col,ct,dek_ver FROM cell');
    const out: compartment.DecryptedCell[] = [];
    for (const r of rows) {
      const dek = await getDEK(r.resource, r.dek_ver);
      if (!dek) continue;
      try { out.push({ tbl: 'notes', rowId: r.rid, col: r.col, resource: r.resource, hlc: j(r.dek_ver, r.resource), value: await C.aeadDecrypt(dek, r.ct) }); } catch { /* skip */ }
    }
    return out;
  };
  const isArchived = async (rid: string): Promise<boolean> => Number(await conn().scalar<number>('SELECT flag FROM archived WHERE rid=?', [rid]) ?? 0) === 1;

  const listNotes = async (): Promise<Array<{ id: string; title: string | null; body: string | null }>> => {
    const records = compartment.foldRecords(await decryptedCells());
    const ridsRows = await conn().all<{ rid: string }>('SELECT DISTINCT rid FROM cell ORDER BY rid');
    const out: Array<{ id: string; title: string | null; body: string | null }> = [];
    for (const { rid } of ridsRows) {
      if (await isArchived(rid)) continue;
      const rec = records.get(compartment.recordKey('notes', rid));
      out.push({ id: rid, title: rec?.get('title') ?? null, body: rec?.get('body') ?? null });
    }
    return out;
  };
  const myRole = async (): Promise<Role | null> => {
    if (!state.session || !state.conn) return null;
    if (state.session.edPub === (await adminPub())) return 'admin';
    const u = (await knownUsers()).find((x) => x.pub === state.session!.edPub);
    return u ? u.role : 'none';
  };
  const heldResources = async (): Promise<string[]> => {
    if (!state.session) return [];
    if (await isAdmin()) return (await conn().all<{ resource: string }>('SELECT DISTINCT resource FROM cell UNION SELECT DISTINCT resource FROM grantrec')).map((r) => r.resource);
    return (await conn().all<{ resource: string }>("SELECT resource FROM grantrec WHERE subject=? AND revoked=0 AND role IN ('reader','writer')", [state.session.edPub])).map((r) => r.resource);
  };

  const consolidate = async (): Promise<ConsolidatedRecord[]> => {
    const records = compartment.foldRecords(await decryptedCells());
    const rids = (await conn().all<{ rid: string }>('SELECT DISTINCT rid FROM cell ORDER BY rid')).map((r) => r.rid);
    const out: ConsolidatedRecord[] = [];
    for (const rid of rids) {
      const rec = records.get(compartment.recordKey('notes', rid));
      const cols: Record<string, string | null> = {};
      if (rec) for (const [k, v] of rec) cols[k] = v;
      const resources = (await conn().all<{ resource: string }>('SELECT DISTINCT resource FROM cell WHERE rid=?', [rid])).map((r) => r.resource);
      out.push({ tbl: 'notes', rowId: rid, cols, resources, archived: await isArchived(rid) });
    }
    return out;
  };

  /* ---- sync: export + authorize-at-import (staging) ----------------------*/
  const exportChangeset = async (since = -1): Promise<string> => conn().exportChangesetSQL(since);

  // Content hash of the converged data — equal on two replicas iff they hold the
  // same cell/grant/identity state (a visible "in sync" check for the UI).
  const stateRoot = async (): Promise<string> => {
    if (!state.conn) return C.EMPTY_ROOT;
    const rows = await conn().all<{ s: string }>(
      `SELECT group_concat(pk||':'||coalesce(ct,'')||':'||coalesce(dek_ver,'')) AS s
       FROM (SELECT pk,ct,dek_ver FROM cell ORDER BY pk)`);
    const grants = await conn().all<{ s: string }>(
      `SELECT group_concat(pk||':'||role||':'||revoked) AS s FROM (SELECT pk,role,revoked FROM grantrec ORDER BY pk)`);
    return C.sha256hex((rows[0]?.s ?? '') + '|' + (grants[0]?.s ?? ''));
  };

  /* ---- consensus checkpoints (step 1) ------------------------------------
   * A LOCK records a signed checkpoint {hash, epoch, parent, vv, members}. The
   * chain of checkpoints is the sequence of agreed group states; `vv` is the
   * version vector at that point, so a peer can diff "ops since checkpoint H". */
  const checkpoints = async (): Promise<consensus.Checkpoint[]> =>
    conn().all<consensus.Checkpoint>('SELECT hash, epoch, parent FROM checkpoint');
  const latestCheckpoint = async (): Promise<string> => consensus.tip(await checkpoints());

  const localDbVersion = async (): Promise<number> => Number(await conn().scalar('SELECT crsql_db_version()') ?? 0);
  // Snapshot our LOCAL db_version as the watermark for a checkpoint we now hold,
  // so exportSince(hash) = our writes with db_version > watermark. Local, not a CRR.
  const setWatermark = async (hash: string): Promise<void> => {
    await conn().run('INSERT OR IGNORE INTO _wm(hash,dbv) VALUES(?,?)', [hash, await localDbVersion()]);
  };

  /** Record a signed consensus checkpoint over the current state (admin only). */
  const recordCheckpoint = async (): Promise<string> => {
    if (!(await isAdmin())) throw new Error('admin only');
    const cps = await checkpoints();
    const parent = consensus.tip(cps);
    const epoch = cps.reduce((m, c) => Math.max(m, c.epoch), -1) + 1;
    const members = JSON.stringify((await conn().all<{ pub: string }>('SELECT pub FROM identity ORDER BY pub')).map((r) => r.pub));
    const hash = await C.sha256hex(j('checkpoint', await stateRoot(), epoch, parent));
    const row = { hash, epoch, parent, members };
    const sig = await sign(sigInput.checkpoint(row));
    await conn().run('INSERT OR REPLACE INTO checkpoint(hash,epoch,parent,members,author,sig) VALUES(?,?,?,?,?,?)',
      [hash, epoch, parent, members, session().edPub, sig]);
    await setWatermark(hash);
    return hash;
  };

  /** Export the diff of ops we've added since we adopted a checkpoint (using our
   *  LOCAL db_version watermark — cr-sqlite's db_version isn't portable). */
  const exportSince = async (checkpointHash: string): Promise<string> => {
    const dbv = await conn().scalar<number>('SELECT dbv FROM _wm WHERE hash=?', [checkpointHash]);
    if (dbv === null) throw new Error('unknown checkpoint (no local watermark)');
    return conn().exportChangesetSQL(Number(dbv));
  };

  // Read the asserted rows out of a staging conn, verify each row's embedded
  // signature, and check the embedded author's grant against MAIN. Returns the
  // list of rejection reasons (empty = all authorized).
  const authorizeStaging = async (staging: Conn): Promise<string[]> => {
    const bad: string[] = [];
    const mainAdmin = await adminPub();
    const sAdmin = await staging.scalar<string>("SELECT pub FROM adminroot WHERE k='root'");
    if (sAdmin && mainAdmin && sAdmin !== mainAdmin) bad.push('conflicting admin root');
    const admin = mainAdmin ?? sAdmin; // TOFU when we have none yet
    const isAdminAuthor = (a: string): boolean => a === admin;

    // 1. SYSTEM rows must be sig-valid + admin-authored (self for identity).
    //    These establish the trusted grant state we authorize cells against.
    for (const r of await staging.all<{ pub: string; name: string; xpub: string; author: string; sig: string }>('SELECT pub,name,xpub,author,sig FROM identity')) {
      if (!await C.verifyMessage(sigInput.identity(r), r.sig, r.author)) bad.push(`identity ${r.name}: bad sig`);
      else if (!(r.author === r.pub || isAdminAuthor(r.author))) bad.push(`identity ${r.name}: not self/admin`);
    }
    for (const r of await staging.all<{ resource: string; ver: number; author: string; sig: string }>('SELECT resource,ver,author,sig FROM dekver')) {
      if (!await C.verifyMessage(sigInput.dekver(r), r.sig, r.author)) bad.push(`dekver ${r.resource}: bad sig`);
      else if (!isAdminAuthor(r.author)) bad.push(`dekver ${r.resource}: not admin`);
    }
    for (const r of await staging.all<{ subject: string; resource: string; role: string; revoked: number; epoch: number; author: string; sig: string }>('SELECT subject,resource,role,revoked,epoch,author,sig FROM grantrec')) {
      if (!await C.verifyMessage(sigInput.grantrec(r), r.sig, r.author)) bad.push(`grant ${r.subject}/${r.resource}: bad sig`);
      else if (!isAdminAuthor(r.author)) bad.push(`grant ${r.subject}/${r.resource}: not admin`);
    }
    for (const r of await staging.all<{ subject: string; resource: string; dek_ver: number; box: string; author: string; sig: string }>('SELECT subject,resource,dek_ver,box,author,sig FROM keywrap')) {
      if (!await C.verifyMessage(sigInput.keywrap(r), r.sig, r.author)) bad.push(`keywrap ${r.subject}: bad sig`);
      else if (!isAdminAuthor(r.author)) bad.push(`keywrap ${r.subject}: not admin`);
    }
    for (const r of await staging.all<{ hash: string; epoch: number; parent: string; members: string; author: string; sig: string }>('SELECT hash,epoch,parent,members,author,sig FROM checkpoint')) {
      if (!await C.verifyMessage(sigInput.checkpoint(r), r.sig, r.author)) bad.push(`checkpoint ${r.hash}: bad sig`);
      else if (!isAdminAuthor(r.author)) bad.push(`checkpoint ${r.hash}: not admin`);
    }
    if (bad.length) return bad; // don't trust staging's grant state if system rows are tainted

    // 2. DATA rows: sig-valid + author is a writer per the effective grant state
    //    = MAIN's grants (already trusted) ∪ STAGING's (admin-verified above). An
    //    incremental diff carries new cells but not old grants (those are in main).
    for (const r of await staging.all<{ pk: string; resource: string; ct: string; dek_ver: number; author: string; sig: string }>('SELECT pk,resource,ct,dek_ver,author,sig FROM cell')) {
      if (!await C.verifyMessage(sigInput.cell(r), r.sig, r.author)) bad.push(`cell ${r.pk}: bad sig`);
      else if (!(await writerIn(staging, admin, r.author, r.resource)) && !(await writerIn(conn(), admin, r.author, r.resource))) bad.push(`cell ${r.pk}: author lacks writer on ${r.resource}`);
    }
    for (const r of await staging.all<{ rid: string; flag: number; author: string; sig: string }>('SELECT rid,flag,author,sig FROM archived')) {
      if (!await C.verifyMessage(sigInput.archived(r), r.sig, r.author)) bad.push(`archived ${r.rid}: bad sig`);
    }
    return bad;
  };

  const importChangeset = async (changesetSQL: string): Promise<ImportResult> => {
    if (!changesetSQL.trim()) return { applied: true, rejected: [], stateRoot: await stateRoot() };
    if (!state.conn) { state.conn = await engine.openMain(await vfsKey()); await initSchema(state.conn); }
    // Authorize against a throwaway staging conn that holds only the asserted
    // rows (readable). adminroot is a CRR, so it travels and TOFU works here.
    const staging = await engine.openStaging();
    try {
      await initSchema(staging);
      await staging.applyChangesetSQL(changesetSQL);
      const rejected = await authorizeStaging(staging);
      if (rejected.length) return { applied: false, rejected, stateRoot: await stateRoot() };
      await conn().applyChangesetSQL(changesetSQL); // carries adminroot (CRR) into main
      dekCache.clear();
      // snapshot a local watermark for any checkpoints we now hold but hadn't seen
      for (const { hash } of await conn().all<{ hash: string }>('SELECT hash FROM checkpoint WHERE hash NOT IN (SELECT hash FROM _wm)')) await setWatermark(hash);
      return { applied: true, rejected: [], stateRoot: await stateRoot() }; // for merge-confirm
    } finally {
      await staging.close();
    }
  };
  // Sync helper for tests: pull another device's full state into this one.
  const syncFrom = async (other: { exportChangeset: (s?: number) => Promise<string> }): Promise<ImportResult> =>
    importChangeset(await other.exportChangeset(-1));

  /* ---- wipe-and-rebuild consensus loop (step 4) --------------------------
   * At a group consensus the coordinator merges everyone's diffs, optionally
   * rotates DEKs, records a checkpoint, then hands each member a REBUILD SLICE:
   * a self-contained changeset with the auth/checkpoint state + only the cells
   * for resources that member may read, MINUS archived records. The member then
   * wipes their local store and rebuilds from the slice — this is the
   * compaction + data-minimization + redistribution step. */

  // resources a subject may read (reader or writer, not revoked)
  const readableBy = async (subjectPub: string): Promise<string[]> =>
    (await conn().all<{ resource: string }>("SELECT DISTINCT resource FROM grantrec WHERE subject=? AND revoked=0 AND role IN ('reader','writer')", [subjectPub])).map((r) => r.resource);

  // copy full table rows from main → a target conn (preserves author+sig)
  const copyTable = async (to: Conn, table: string, cols: string[], where = ''): Promise<void> => {
    const rows = await conn().all<Record<string, SqlValue>>(`SELECT ${cols.join(',')} FROM ${table} ${where}`);
    const ph = cols.map(() => '?').join(',');
    for (const r of rows) await to.run(`INSERT OR REPLACE INTO ${table}(${cols.join(',')}) VALUES(${ph})`, cols.map((c) => r[c]));
  };

  /** Build a member's rebuild slice: auth/checkpoint state + their entitled,
   *  non-archived cells. Admin only. Returns a changeset the member imports into
   *  a freshly wiped store. */
  const rebuildSliceFor = async (subjectPub: string): Promise<string> => {
    if (!(await isAdmin())) throw new Error('admin only');
    const readable = await readableBy(subjectPub);
    const st = await engine.openStaging();
    try {
      await initSchema(st);
      await copyTable(st, 'adminroot', ['k', 'pub']);
      await copyTable(st, 'identity', ['pub', 'name', 'xpub', 'author', 'sig']);
      await copyTable(st, 'grantrec', ['pk', 'subject', 'resource', 'role', 'revoked', 'epoch', 'author', 'sig']);
      await copyTable(st, 'keywrap', ['pk', 'subject', 'resource', 'dek_ver', 'box', 'author', 'sig']);
      await copyTable(st, 'dekver', ['pk', 'resource', 'ver', 'author', 'sig']);
      await copyTable(st, 'checkpoint', ['hash', 'epoch', 'parent', 'members', 'author', 'sig']);
      // entitled, non-archived cells only
      const inList = readable.length ? readable.map((r) => `'${r.replace(/'/g, "''")}'`).join(',') : "''";
      await copyTable(st, 'cell', ['pk', 'rid', 'resource', 'col', 'ct', 'dek_ver', 'author', 'sig'],
        `WHERE resource IN (${inList}) AND rid NOT IN (SELECT rid FROM archived WHERE flag=1)`);
      return await st.exportChangesetSQL(-1);
    } finally {
      await st.close();
    }
  };

  /** Coordinator: merge member diffs, optionally rotate all DEKs, record a
   *  checkpoint. Returns the new checkpoint hash. */
  const runConsensus = async (diffs: string[], opts: { rotate?: boolean } = {}): Promise<string> => {
    if (!(await isAdmin())) throw new Error('admin only');
    for (const d of diffs) await importChangeset(d);
    if (opts.rotate) await rotateAllDeks();
    return recordCheckpoint();
  };

  /** Drop the local store. In :memory: this truly wipes; in the browser the
   *  IndexedDB persists, so a real wipe also deletes the IDB (engine concern). */
  const wipe = async (): Promise<void> => {
    if (state.conn) await state.conn.close();
    state.conn = null;
    dekCache.clear();
  };

  const close = async (): Promise<void> => { if (state.conn) await state.conn.close(); };

  return {
    label,
    get session() { return state.session; },
    login, unlock, exportKeystore, logout, genesis, isAdmin, adminPub, myRole, knownUsers,
    exportIdentityCard, importIdentityCard, grant, revoke, rotateDek, rotateAllDeks, addNote, writeCell, archiveRecord,
    listNotes, heldResources, consolidate, stateRoot,
    recordCheckpoint, checkpoints, latestCheckpoint, exportSince,
    rebuildSliceFor, runConsensus, wipe,
    exportChangeset, importChangeset, syncFrom, close,
  };
};
