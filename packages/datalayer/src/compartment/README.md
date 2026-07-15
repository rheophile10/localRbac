# compartment segment

Pure verbs for the compartmented-RBAC CRDT (see `docs/compartmented-rbac-ceremony.md`).

**Plastron alignment.** This folder is authored to be liftable into
[plastron](/home/ian/projects/plastron/plastron) as a segment of *lockedlambda
cels*:

- **one verb = one exported pure function** (`foldRecords`, `visibleRecords`, …),
  named `compartment.<verb>`;
- **no time, no randomness, no I/O, no input mutation** — `hlc` and keys are passed
  in, values are returned fresh (matches plastron's `crdt` segment discipline);
- a sidecar **`compartment.catalog.json`** carries each verb's one-sentence
  contract in the `{ key, celType:"LockedLambdaCel", metadata, locked:true }` shape
  — the future `甲骨.json`. Its keys line up 1:1 with the `index.ts` exports.

The lift later is mechanical: wrap each export as an `Fn` and `bindNativeFns(seed,
map)`. Effectful concerns (encryption, timestamps, storage) stay OUT of these
verbs and live at the call site / in the crypto segment.
