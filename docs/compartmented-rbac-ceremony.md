# Compartmented RBAC + Lock / Unlock / Distribute Ceremony — Design

Status: **design, pending confirmation**. This reshapes the datalayer core
(per-resource encryption + an index table), so it is written down before build.

## 1. Resources (compartments)

- A **resource** is the unit of permission. Users hold **grants** `{resource, role:
  reader | writer}` (our `_grant` table already keys on `resource`).
- There is a **data-key (DEK) per `(resource, version)`**. Only holders of that DEK
  can decrypt that resource's ciphertext. DEKs are **ephemeral** — minted fresh at
  each unlock (see §5), never stored in the consolidated truth.

## 2. Records and the index table

- Records live in tables (`notes`, …). **A record may be tagged to *many*
  resources** (many-to-many).
- **Index table** — the mapping that drives encryption, filtering, and
  consolidation:
  ```
  record_resource(tbl TEXT, row_id TEXT, resource TEXT, PRIMARY KEY(tbl,row_id,resource))
  ```
  A tag (record ↔ resource) is added/removed by a signed CRDT op like any other.

## 3. Per-resource encryption (CONFIRMED — multiple ciphertexts per record)

- Each **cell-write op** carries a `resource` + `dek_ver`; its `val` is
  AEAD-encrypted under `DEK(resource, dek_ver)`. A record tagged to N resources
  therefore has **up to N ciphertexts** (one per resource it is edited under).
- A record's materialized state = **LWW merge across every op the reader can
  decrypt**, over all resources that record is tagged to *and* the reader holds a
  DEK for. This is "merge each resource version of a record".
- A user can see a record **iff** they hold a DEK for ≥1 resource it is tagged to.

**Motivating example.** Each patient is a resource. A patient holds a grant only
for their own resource, so they can read only their own records. A record can be
tagged to several resources. Only a party who holds the DEKs for **all** the
resources on a record (e.g. a doctor with all-patient permissions) can decrypt and
LWW-merge that record's resource-versions into a single consolidated artifact.

## 4. LOCK (close-out) — requires an **archive** key and a **backup** key

The locker **cannot begin** without both the archival public key and the backup
public key. **The locker must hold read (DEK) access to EVERY resource present in
the set being locked** — if they lack any resource's DEK they cannot produce a
merged, consolidated artifact for those records (the patient/doctor rule from §3).

1. **Consolidate.** For every resource the locker can decrypt, decrypt its ops and
   LWW-merge per record → **plaintext** record state.
2. **Split** archived vs active by each record's `archived` flag.
3. **Active vault** = the active plaintext records + the index table (tags) +
   roster/grants, with **no DEKs, no keywraps, no ciphertext**. Sealed **k-of-n**
   to the custodian quorum → `truth-<date>.vault` (unlocked next morning).
4. **Archive dump** = the archived plaintext records + their tags, encrypted to the
   **archival public key** → `archive-<date>.sealed` (archivist only).
5. **Backup diff** = the day's **consolidated delta** (since the morning
   watermark), encrypted to the **backup public key** → `backup-<date>.enc`,
   routed to a **separate backup store** (an out-of-band file on `file://`).

## 5. UNLOCK (morning, distributed — no hot-seat)

Reproduces regina's contribution-file model:

1. **Opener** loads the active vault + their own key → seeds their own share.
2. Each **custodian** runs `produceContribution` — decrypts their share and
   **re-seals it to the opener's key** → a contribution file.
3. Opener runs `importContribution` per file; at ≥ k shares, reconstruct the vault
   key → decrypt the **plaintext** consolidated truth.
4. **Mint NEW per-resource DEKs** (fresh version). Re-encrypt each record's cells
   under the DEK of every resource it is tagged to (from the index table). Issue
   keywraps to users per their grants. → the day's working truth, freshly keyed.

## 6. DISTRIBUTE (on unlock)

For each user U, build a **slice** = records tagged to resources U can read
(grants ∩ index table), **encrypted to U's public key** → a file U downloads into
their own `index.html` and starts working on. Writers also receive the DEK
keywraps for resources they may write.

## 7. Archiving

A record carries an `archived` flag (set by a signed op). Lock (§4.2) pulls
archived records out of the active truth into the archive dump (§4.4).

## Key roles summary

| Key | Held by | Opens |
|---|---|---|
| Custodian identity keys (X25519) | the n custodians | the active vault (k-of-n quorum) |
| Archival public key | the archivist | the archive dump |
| Backup public key | the backup store | the day's backup diff |
| Per-resource DEKs | users, per grant (keywraps) | that resource's records — **re-minted every unlock** |

## Confirmed

1. **§3** — ops encrypted per-resource; **multiple ciphertexts per record**; a
   record = LWW across resource-versions. (Patient/doctor example.)
2. **Locking requires the locker to hold DEKs for ALL resources being locked.**
3. Active vault = full consolidated state; backup = **diff since morning**; archive
   = the archived subset.
4. Archive dump and backup diff are **single-recipient** (their public key); only
   the **active** truth uses the k-of-n custodian quorum.

## Future: Plastron alignment (structural constraint)

This code should eventually be liftable into **plastron** as "lockedlambda cels"
and "formulas", grouped into mergeable "segment" files. So: prefer **pure
functions with explicit inputs/outputs, one verb-like operation per file, minimal
side effects**, grouped by domain into folders that could become segments. Exact
conventions pending a study of `/home/ian/projects/plastron`; the datalayer's
per-domain crypto layout already leans this way.
