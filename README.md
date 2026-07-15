# localRbac

A working demonstration that **role-based access control can be enforced purely by
public-key cryptography** — no server, no online authority at access time — over a
**local-first CRDT database** stored in an ordinary SQLite file opened from `file://`.

The app is one self-contained `dist/index.html` (SQLite-WASM + crypto inlined; zero
external fetches). A second page, `dist/demo.html`, **iframes that app three times**
so you can watch three users collaborate on one screen.

![three users, converged and interleaved](shots/03-interleaved.png)

## What it demonstrates

Premise: on a local file there is no server to check permissions, and you cannot
stop someone reading the bytes on their own disk. So access control must be
*cryptographic*, and must survive the file being copied, edited offline, and merged.

- **Roles** — read+write, read-only, denied — provisioned per user by an admin.
- **Read control is encryption.** Records are encrypted; only users the admin sealed
  the data-key to can decrypt. A denied user holding the same data sees `🔒`.
- **Write control is signatures + policy.** Every change is Ed25519-signed and is
  accepted on merge only if the author holds an admin-signed *writer grant*. Forged
  or unauthorized changes are **rejected at merge**, not hidden in the UI.
- **Everything is one signed op-log** — identities, grants, key-wraps, the admin
  root, the data-key version, and the records themselves are all ops. So an
  **ops-only difflog** fully reconstructs state on a fresh machine, and merge stays
  commutative, associative, idempotent → **convergent**.

## How it works on local files

Each participant keeps two files: `index.html` (the app, identical for everyone) and
their own `*.sqlite` (the data — the shared document). **They never connect.** They
collaborate by exchanging deltas:

- **Sign in** — name + passphrase deterministically derive an Ed25519/X25519 keypair
  (Argon2id — memory-hard, so a stolen file is expensive to brute-force offline).
  Nothing is stored; the same credentials reproduce the same identity.
- **Admin** is whoever creates the genesis DB; their key is pinned as the root of
  trust (trust-on-first-use), carried in the op-log so it propagates.
- **Provision users** — admin creates a user by initial credentials and assigns a
  role (a demo simplification; a real deploy exchanges public keys, not passwords).
- **Difflog** — the unit of exchange: `{ baseHash, ops }`, a delta of signed ops
  since a marked baseline, stamped with `stateRoot()` — a content **hash of the base
  op-set**. Export it, send it (email/USB/drive), the other side imports & merges.
- **State root** — a SHA-256 over the sorted op-ids. Two replicas showing the same
  root have **converged**; it's how you verify sync without shipping data.

Concurrent writers **interleave** deterministically: each op carries a Hybrid
Logical Clock, so after everyone merges everyone's difflogs, all replicas show the
same time-ordered, interleaved list (see the screenshot / video).

### The demo (`dist/demo.html`) is a simulation of that exchange
Three iframes = three machines. In real use each is a different person, and moving a
difflog between them is *saving a file and sending it*. The Dump/Load `.sqlite`
buttons are the genuine full-file path; the difflog textareas are the delta path.

## Where enforcement lives (`src/device.ts`)

| Concern | Mechanism | Functions |
|---|---|---|
| Write control | Ed25519 sig + admin grant, checked on append **and** at merge | `authorizeNoteWrite`, `mergeOps` |
| Read control | xchacha20 record encryption; data-key sealed (X25519) per reader | `getDEK`, `tryDecrypt` |
| Roles / root | admin-signed ops; admin pinned trust-on-first-use | `authorizeSystemOp`, `provisionUser`, `grant`, `revoke` |
| Read revocation | data-key rotation + re-seal to remaining readers | `rotateDek` |
| Diff / convergence | content hash of the op-set; delta since a baseline | `stateRoot`, `markBaseline`, `exportDiff`, `importDiff` |

## Crypto architecture (swappable per domain)

Cryptography lives behind a small abstraction so any protocol or dependency can
be swapped in one place. Each **functional domain** has an `index.ts` exporting
the business functions, backed by a concrete implementation file:

```
src/crypto/
  index.ts            composes the business API (deriveIdentity, signOp, sealTo, …)
  kdf/     → hash-wasm Argon2id   (memory-hard password derivation; WASM; async)
  signing/ → noble Ed25519        (write authorization)
  sealing/ → noble X25519 box     (read control: seal a data-key to a reader)
  aead/    → noble xchacha20poly  (record encryption)
  hash/    → noble sha256/hkdf    (state root + key expansion; sync)
  util.ts  hex / utf8 / random / concat
```

To change, say, the KDF or the signature scheme, edit the one `export … from`
line in that domain's `index.ts`; `device.ts`, `ui.ts`, and the rest of
`crypto/index.ts` are untouched. `crypto.PROTOCOLS` reports what's wired in.

Notes:
- **KDF is Argon2id via hash-wasm** — memory-hard (64 MiB), so a stolen file is
  expensive to brute-force offline; ~10× faster than a pure-JS KDF, which is why
  we can afford the strong parameters. It's WASM, so `deriveIdentity` (and thus
  `login`/`provisionUser`) are **async**. The Argon2 parameters are a protocol
  constant — every participant must match them.
- Both WASM modules (SQLite + Argon2) are base64-inlined → still zero fetches on
  `file://`.

## Threshold custody — seal / unlock ceremony (`packages/datalayer/src/vault.ts`)

Lock a payload (e.g. a full database dump) so **no single person can open it** —
only a quorum of **k-of-n custodians** cooperating. Modelled on regina's
threshold custody, using our own X25519 identities instead of RSA:

- `sealVault(payload, custodians, k)` → random data-key (DEK) → encrypt payload
  (xchacha20) → **Shamir-split** the DEK k-of-n (GF(2⁸)) → seal share *i* to
  custodian *i*'s X25519 public key. Returns a `SealedVault` (no secret is
  recoverable below quorum).
- `contributeShare(vault, identity)` → a custodian unseals their one share (null
  if they aren't a custodian).
- `openVault(vault, shares)` → needs ≥ k shares → combine → DEK → decrypt. Fewer
  or wrong shares **fail closed** (AEAD tag). DEK is zeroed after use.
- `quorumFor(n, ratio=0.8)` → default 4-of-5.

Shamir only controls *who can reassemble the DEK*; confidentiality rests on the
AEAD. Covered by `packages/datalayer/tests/{shamir,vault}.test.ts`.

**Recipient-targeted merge files** (`device.sealDiffFor` / `openSealedDiff`): a
difflog sealed to one recipient's key, so two users can hand each other merge
files only they can open (the ops inside are still individually signed).

## Monorepo layout

Two packages: a headless **datalayer** (the engine) and an **app** that wires it
to the UI and produces the single `index.html`.

```
packages/
  datalayer/            @localrbac/datalayer — headless, no DOM, no build tooling
    src/
      index.ts          barrel: createDevice, crypto, vault, types
      device.ts         CRDT + RBAC engine (one per user)
      vault.ts          threshold-custody seal/unlock ceremony
      types.ts
      crypto/           per-domain crypto (kdf/signing/sealing/aead/hash/secret-sharing)
    tests/              Vitest — engine, shamir, vault (headless, no browser)
  app/                  @localrbac/app — Vite + TS → dist/index.html
    index.html          one app instance (one user)
    public/demo.html    static shell that iframes the built app 3x
    src/                ui.ts, main.ts, style.css   (imports @localrbac/datalayer)
    vite.config.ts      singlefile + inlines SQLite WASM; aliases the datalayer source
    tests/rbac.spec.ts  Playwright — drives the 3-iframe demo end to end
    scripts/            shots.ts, record.ts
```

## Build, run, test (from the repo root)

```
npm install             # installs both workspaces
npm run build           # -> packages/app/dist/index.html + demo.html
npm run dev             # hot-reloading dev server (open /demo.html for 3-up)
open packages/app/dist/demo.html   # the three-user demo, on file://

npm run typecheck       # both packages (tsc --noEmit, strict)
npm run test:unit       # datalayer Vitest — RBAC, shamir, vault
npm run test:e2e        # build app -> Playwright
npm test                # typecheck -> unit -> build -> e2e
npm run shots           # regenerate packages/app/shots/
npm run record          # regenerate packages/app/videos/*.webm (captioned slow-mo)
```

Artifacts: `shots/*.png`, `videos/rbac-difflog-demo.webm` (~50s captioned walkthrough).
