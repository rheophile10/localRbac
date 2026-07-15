/* The new engine spine: cr-sqlite convergence over SIGNED changesets, with
 * forgery rejected at the sync boundary. Proves the transport + auth foundation
 * the compartmented-RBAC engine will build on. Runs in Node on the :memory: VFS.*/
import { describe, it, expect, beforeAll } from 'vitest';
import { bootNodeEngine } from './helpers/boot-node';
import { Conn } from '../src/engine/sqlite';
import * as C from '../src/crypto';
import type { Identity } from '../src/types';

let engine: Awaited<ReturnType<typeof bootNodeEngine>>;
let alice: Identity, mallory: Identity;

const SCHEMA = `
  CREATE TABLE cell(id TEXT NOT NULL PRIMARY KEY, rid TEXT, resource TEXT, col TEXT, ct TEXT);
  SELECT crsql_as_crr('cell');
`;

// A changeset signed by its author — the unit two users exchange.
interface SignedChangeset { author: string; sql: string; sig: string; since: number; upto: number; }
const sign = async (sql: string, id: Identity, since: number, upto: number): Promise<SignedChangeset> =>
  ({ author: id.edPub, sql, sig: await C.signMessage(sql, id.edPriv), since, upto });
const verifyAndApply = async (conn: Conn, cs: SignedChangeset): Promise<'applied' | 'rejected'> => {
  if (!(await C.verifyMessage(cs.sql, cs.sig, cs.author))) return 'rejected';
  await conn.applyChangesetSQL(cs.sql);
  return 'applied';
};

beforeAll(async () => {
  engine = await bootNodeEngine();
  alice = await C.createIdentity('alice');
  mallory = await C.createIdentity('mallory');
});

describe('cr-sqlite spine: signed-changeset convergence', () => {
  it('two independent connections converge via a signed changeset', async () => {
    const a = await engine.openMemory();
    const b = await engine.openMemory();
    await a.exec(SCHEMA);
    await b.exec(SCHEMA);

    // Alice writes an (encrypted) cell locally; cr-sqlite tracks the change
    const dek = C.randomKey();
    await a.run('INSERT INTO cell(id,rid,resource,col,ct) VALUES(?,?,?,?,?)',
      ['c1', 'r1', 'patient:alice', 'body', await C.aeadEncrypt(dek, 'BP 120/80')]);

    // export the delta, sign it, ship to B
    const sql = await a.exportChangesetSQL(-1);
    expect(sql).toContain('crsql_changes');
    const cs = await sign(sql, alice, -1, await a.dbVersion());
    expect(await verifyAndApply(b, cs)).toBe('applied');

    // B converged: same ciphertext row, decrypts with the shared DEK
    const rows = await b.all<{ ct: string; resource: string }>('SELECT ct,resource FROM cell WHERE id=?', ['c1']);
    expect(rows).toHaveLength(1);
    expect(rows[0].resource).toBe('patient:alice');
    expect(await C.aeadDecrypt(dek, rows[0].ct)).toBe('BP 120/80');

    await a.close(); await b.close();
  });

  it('a forged changeset (bad signature) is rejected at the boundary', async () => {
    const a = await engine.openMemory();
    const b = await engine.openMemory();
    await a.exec(SCHEMA); await b.exec(SCHEMA);

    await a.run('INSERT INTO cell(id,rid,resource,col,ct) VALUES(?,?,?,?,?)', ['c9', 'r9', 'patient:alice', 'body', 'x']);
    const sql = await a.exportChangesetSQL(-1);

    // Mallory tampers with the changeset but can't produce Alice's signature
    const tampered: SignedChangeset = { author: alice.edPub, sql: sql.replace('r9', 'r-evil'), sig: await C.signMessage(sql, mallory.edPriv), since: -1, upto: 1 };
    expect(await verifyAndApply(b, tampered)).toBe('rejected');
    expect(await b.all('SELECT * FROM cell')).toHaveLength(0); // nothing applied

    // Mallory re-signs under her OWN key — signature is valid but author != alice;
    // authorization (not tested here) would reject; signature check alone passes,
    // proving the sig is bound to the claimed author.
    const reSigned: SignedChangeset = { author: mallory.edPub, sql, sig: await C.signMessage(sql, mallory.edPriv), since: -1, upto: 1 };
    expect(await C.verifyMessage(reSigned.sql, reSigned.sig, reSigned.author)).toBe(true);
    expect(await C.verifyMessage(reSigned.sql, reSigned.sig, alice.edPub)).toBe(false); // not Alice's

    await a.close(); await b.close();
  });

  it('idempotent + order-independent: applying twice / reversed converges the same', async () => {
    const a = await engine.openMemory();
    const b = await engine.openMemory();
    const c = await engine.openMemory();
    for (const conn of [a, b, c]) await conn.exec(SCHEMA);

    await a.run('INSERT INTO cell(id,rid,resource,col,ct) VALUES(?,?,?,?,?)', ['x1', 'r1', 'res', 'body', 'A']);
    await b.run('INSERT INTO cell(id,rid,resource,col,ct) VALUES(?,?,?,?,?)', ['x2', 'r2', 'res', 'body', 'B']);
    const csA = await a.exportChangesetSQL(-1);
    const csB = await b.exportChangesetSQL(-1);

    // c applies A then B; apply A AGAIN (idempotent)
    await c.applyChangesetSQL(csA);
    await c.applyChangesetSQL(csB);
    await c.applyChangesetSQL(csA);
    // a applies B; b applies A → all three hold {x1,x2}
    await a.applyChangesetSQL(csB);
    await b.applyChangesetSQL(csA);

    for (const conn of [a, b, c]) {
      const ids = (await conn.all<{ id: string }>('SELECT id FROM cell ORDER BY id')).map((r) => r.id);
      expect(ids).toEqual(['x1', 'x2']);
    }
    await a.close(); await b.close(); await c.close();
  });
});
