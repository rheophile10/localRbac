# localRbac

**Role-based access control enforced by cryptography, over a local-first CRDT
database, in one offline HTML file.**

There is no server to check permissions and no network at access time. The data
is a convergent SQLite database ([cr-sqlite](https://github.com/vlcn-io/cr-sqlite))
that participants copy, edit offline, and merge by exchanging signed deltas. Who
may *read* a record is decided by whether you hold the key to decrypt it; who may
*write* is decided by an admin-signed grant checked against every row's signature
**at merge time**. Copy the file, edit it on a plane, hand the delta to a
colleague on a USB stick — the rules survive the trip.

- **Live demo:** <https://rheophile10.github.io/localRbac/demo.html> — three
  users (admin / writer / reader) collaborating on one page.
- **Single-user app:** <https://rheophile10.github.io/localRbac/> — one instance.

## The premise

On a local file you cannot stop someone reading the bytes on their own disk, and
there is no online authority to ask "is this person allowed?". So access control
has to be *cryptographic* and it has to be *portable* — it must still hold after
the file is copied, mutated offline, and merged with someone else's copy.

- **Read control is encryption.** Every record cell is encrypted under a
  per-resource **data-encryption key (DEK)**. You can read a resource only if the
  admin has sealed that DEK to your public key. A user without the key holds the
  same ciphertext and sees `🔒`.
- **Write control is signatures + policy.** Every row carries its author's
  Ed25519 public key and a signature. A change is accepted on merge only if the
  author holds an admin-signed *writer grant* for that resource. Forged or
  unauthorized rows are **rejected at merge**, not merely hidden in the UI.
- **Convergence is cr-sqlite.** The CRDT gives commutative, associative,
  idempotent per-column merge; our RBAC rides on top of `crsql_changes` as the
  transport. Any two replicas that have exchanged everyone's deltas converge to
  the same state.

## Identity: a keystore file you hold, never stored in the browser

Identities are **generated** WebCrypto keypairs (Ed25519 for signing, X25519 for
sealing), not derived from a passphrase. The keypair is wrapped in an
**Argon2id-encrypted keystore file** the user downloads and keeps. It is *never*
written to IndexedDB — stealing the file is a required first step for any offline
attack, and Argon2id (memory-hard) makes the passphrase expensive to brute-force
even then. Provisioning is by **public-key card exchange**: a user exports a
self-signed identity card `{pub, name, xpub, sig}`; the admin imports it and
grants a role to that key, never seeing any private material.

## Compartmented RBAC on cr-sqlite (`packages/datalayer/src/engine/crengine.ts`)

The engine is **resource- and column-agnostic**. Records live in a single generic
entity-attribute-value table; there is no per-record-type schema. The essential
core tables are:

| Table | Role |
|---|---|
| `adminroot` | the admin's pubkey, pinned trust-on-first-use, carried in the op-log |
| `identity` | known public identity cards (self- or admin-signed) |
| `grantrec` | admin-signed `(subject, resource, role)` grants |
| `dekver` | current DEK version per resource (rotation counter) |
| `keywrap` | a resource DEK sealed (X25519) to one subject's key |
| `cell` | `(rid × col)` encrypted value under one resource's DEK + author + sig |
| `archived` | tombstone flag per record |
| `checkpoint` | signed consensus points (hash / epoch / parent / members) |

Everything except a local watermark table is a cr-sqlite CRR, so an ops-only
changeset fully reconstructs state on a fresh machine.

**How the pieces enforce the rules:**

- **Read** — `listRecords` decrypts only the resources you hold a DEK for and
  LWW-folds across compartments. Admin derives every DEK from a root key via HKDF
  (`dek:<resource>` / `v<ver>`); everyone else unseals their DEK from `keywrap`.
- **Write** — `writeCell` refuses locally if you're not a writer, and — the part
  that actually matters — **import re-checks every incoming row**: the changeset
  is applied to a throwaway *staging* connection, each row's signature is
  verified, and each author is checked against the admin-verified grant state
  (main ∪ staging). Only if all rows pass does it merge into the real database.
- **Revoke** — `revoke` writes a revocation and, by default, **rotates the DEK**:
  bump `dekver`, re-seal the new key to the remaining members. The revoked user
  keeps old ciphertext but is locked out of everything written afterward.

## Local consensus vs. group consensus

Two replicas reconcile by exchanging changesets and comparing a **state root** —
a SHA-256 over the sorted cell/grant state. Equal roots ⇒ converged, verified
without shipping the data itself.

For a whole subgroup there is a **consensus ceremony** (`runConsensus`): a
coordinator merges every member's diff-since-the-last-checkpoint, *optionally*
rotates all DEKs, and records a signed **checkpoint**. It then hands each member a
**rebuild slice** — a self-contained changeset with the auth/checkpoint state plus
only the non-archived cells for resources that member may read. Members **wipe
their local store and rebuild from the slice**. That single step does compaction,
data-minimization (you get back only what you're entitled to), and redistribution
of the agreed state. cr-sqlite's `db_version` is a *local* clock (it's reassigned
on merge), so "diff since checkpoint H" uses a local watermark, not a portable
version vector — a subtlety that bit us and is documented in the code.

## Threshold custody — no single keyholder on the critical path (`packages/datalayer/src/vault.ts`)

A full database dump (or any payload) can be sealed so that **no one person can
open it** — only a quorum of **k-of-n custodians** cooperating.
[Shamir's secret sharing](https://dl.acm.org/doi/10.1145/359168.359176) splits a
random DEK into `n` shares over GF(2⁸); reconstructing it needs any `k`. Each
share is then sealed to one custodian's X25519 key.

- `sealVault(payload, custodians, k)` → encrypt under a random DEK → Shamir-split
  the DEK → seal share *i* to custodian *i*. Nothing is recoverable below quorum.
- Distributed unlock (no hot-seat): each custodian re-seals their share to the
  chosen opener; the opener combines ≥ k → DEK → decrypts. Fewer/wrong shares
  **fail closed** on the AEAD tag; the DEK is zeroed after use.

The point is human, not just cryptographic: a group can keep records together
without making any single member worth coercing. No one holder is a
[$5-wrench](https://xkcd.com/538/) single point of failure. Shamir only governs
*who can reassemble the key*; confidentiality still rests on the AEAD.

## Crypto architecture (swappable per domain)

Each cryptographic concern is a folder with an `index.ts` that picks a concrete
implementation, so a protocol can be swapped in one place:

```
packages/datalayer/src/crypto/
  kdf/            → hash-wasm Argon2id   (memory-hard keystore wrapping)
  signing/        → WebCrypto Ed25519    (write authorization)
  sealing/        → WebCrypto X25519 box (seal a DEK to a reader)
  aead/           → WebCrypto AES-256-GCM (record + payload encryption)
  hash/           → WebCrypto SHA-256/HKDF (state root + DEK derivation)
  secret-sharing/ → Shamir over GF(2⁸)   (the one hand-rolled primitive)
```

Almost everything is native WebCrypto — fast, dependency-free, and it works on
`file://`. The sync-critical IndexedDB page cipher is the one exception (it must
be synchronous because an IndexedDB transaction auto-commits across an `await`),
so it keeps `@noble/ciphers` xchacha20. Both WASM blobs (SQLite + Argon2) are
base64-inlined → **zero network fetches**, even on `file://`.

## Monorepo layout

A headless **datalayer** (the engine) and an **app** that wires it to a UI and
produces the single `index.html`. The datalayer knows nothing about "notes" — the
notes convention (title/body columns, seeds, UI) lives entirely in the demo.

```
packages/
  datalayer/            @localrbac/datalayer — headless, no DOM
    src/
      engine/crengine.ts    compartmented-RBAC engine on cr-sqlite
      vault.ts              threshold-custody seal/unlock ceremony
      consensus/            checkpoint-chain pure verbs
      compartment/          per-resource decrypt + LWW fold
      crypto/               per-domain crypto (see above)
    tests/                  Vitest — engine, consensus, rotation, rebuild, shamir, vault
  app/                  @localrbac/app — Vite + TS → dist/index.html
    src/notes.ts            the "notes" demo convention on the generic engine
    src/ui.ts, main.ts      vanilla-DOM UI for one device
    public/demo.html        iframes the built app 3× (three users, one page)
    tests/rbac.spec.ts      Playwright — drives the 3-iframe demo end to end
```

## Build, run, test

```bash
npm install
npm run build              # -> packages/app/dist/{index.html, demo.html}
npm run dev                # hot-reloading dev server (open /demo.html for 3-up)
npm run typecheck          # both packages, strict
npm run test:unit          # datalayer Vitest (RBAC, consensus, shamir, vault)
npm run test:e2e           # build -> Playwright against the 3-iframe demo
```

## Group key agreement — MLS (RFC 9420, `packages/datalayer/src/mls/`)

A subgroup can run an **MLS group** for group-native key agreement and
messaging, via [`ts-mls`](https://github.com/LukaJCB/ts-mls) — a pure-TypeScript
RFC 9420 implementation over WebCrypto, **no WASM and no network**, so it bundles
into the same single `file://` HTML (proven: `packages/app/mls-spike.ts` runs a
full handshake in one self-contained file).

- Every member independently derives the **same per-resource DEK at each epoch**
  (`mlsExporter`) — replacing per-reader X25519 keywraps with one group secret.
- **Add / remove** advances the epoch, so the group key **rotates with forward +
  post-compromise security** — the "rotate the DEK at consensus" primitive, made
  group-native.
- Authenticated **group application messages** (`send` / `receive`).

The verbs are pure (`state → new state`) and resource-agnostic; the ciphersuite
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, matching our X25519/Ed25519/
AES-GCM/SHA-256 stack) and exporter label are protocol constants.

## Status

Proof of concept. Implemented: consensus checkpoints, merge-confirm by state
root, optional DEK rotation, the wipe-and-rebuild consensus loop, and MLS group
key agreement + messaging (headless + verified in the single-file `file://`
build). Wiring MLS-derived group keys in as the primary DEK source for the
compartmented engine (replacing per-reader keywraps) is the next integration
step.

## References

- [Shamir, *How to Share a Secret*, CACM 1979](https://dl.acm.org/doi/10.1145/359168.359176)
- [xkcd 538 — *Security*](https://xkcd.com/538/)
- [cr-sqlite](https://github.com/vlcn-io/cr-sqlite) — convergent replicated SQLite
