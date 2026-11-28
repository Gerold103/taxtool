# Roadmap

## Agreed design

Decisions taken in discussion, recorded here so that code follows them
and nobody re-derives them. `doc/risks.md` holds what they prove.

- The data directory holds `.tax/`, owned by taxtool, next to the user's
  files. Inside it, `.tax/.vault/` is owned by the vault: the object
  store, seals and proofs, the authorities' configuration and material,
  the stat cache. The vault receives the data root and its own home
  directory as parameters and knows neither the name `.tax` nor taxes.
- A seal covers every file under the data root, `.tax/` included, except
  the object store and the stat cache under `.tax/.vault/`. Earlier
  seals are ordinary files to the next seal, so a completed proof, an
  abandoned proof or a changed config shows up as a change the next seal
  records. Each seal names the previous seal's root hash, forming one
  chain, and names the authorities it attempted, so that a missing proof
  is a finding and not an unknown.
- A seal records the data root as tree objects, git's model: one YAML
  listing per directory, each entry naming a file or a child listing by
  digest, stored in the object store. The seal names the root listing's
  digest. Every seal therefore describes the complete data root and
  verifies on its own, while an unchanged subtree is one object shared
  by every seal since it last changed. A full manifest per seal was
  rejected for size, and a list of changes per seal because it puts each
  file's hash in exactly one seal, where one lost record hides an
  alteration. Deduplication lives in the store, below the proof, so the
  storage encoding can change later without touching any seal.
- There is one object store, `.tax/.vault/objects/`, holding the bytes
  of every file a seal lists and the tree objects that list them, so the
  store is a full copy of the business directory plus every past version
  of a changed file, deduplicated by hash. Its contents are reached by
  hash from the seals' trees, which is why the scan excludes it. Nothing
  in it is deleted before phase 2, where `gc` keeps whatever any seal's
  tree still reaches. Refs, names pinning blobs, were considered and
  dropped: an event's path plus the covering seal's tree is the same
  binding, and the tree pins the bytes.
- Phase 2 builds on the trees: `checkout` rebuilds the data root as it
  was at a seal from the trees and the store, and `reset --hard` does
  the same in place for the last seal. `diff` shows the content
  difference between two
  seals, or a seal and the working tree: line by line for text files
  such as logs and config, by hash and size for documents, not merely
  which paths changed and what event that is. `archive` and `expire`
  work per subtree, and `export` can hand over a subtree with the
  listings on its path to the root as a self-contained proof of that
  subtree.
- The vault reports the difference since the last seal as events: the
  specific ones it recognises in its own files, such as a proof
  completed, a proof abandoned, a seal tampered, a seal removed, the
  chain extended or cut, and the generic file added, changed or deleted
  for everything else. taxtool interprets them, for example a changed
  `config.yaml`, and chooses the wording of `status`.
- Sealing attempts at least one configured authority and requires none
  to be complete: a Bitcoin-anchored proof is Pending for hours. A
  pending proof is completed later, for one chosen seal or for all. A
  proof whose authority has died is abandoned explicitly, which writes a
  marker file next to it; nothing in a proof directory is ever rewritten.
- The local HMAC authority is the fully offline authority and is
  configurable by users like any other; it proves nothing to third
  parties. RFC 3161 supplies the precise time, OpenTimestamps the
  "existed no later than this block" bound. Both are wanted on a seal.

## Phase 1: records and seals
- `init`, `check`, `status`, `seal`, `verify`, `reset`.
- Documents as entries of typed owner's files whose copies the vault
  keeps, classified through a stage that `seal` turns into events:
  `add document`, `rm document`, `reset`, `doc list`, `doc show`,
  `doc export`; see `doc/tax/documents.md`.
- Manual event entry from `templates/`.
- Local HMAC, RFC 3161 and OpenTimestamps authorities; `seal complete`
  and abandoned-proof markers.
- The business directory as `doc/tax/layout.md` lays it out: the
  owner's files in any layout, `.taxignore`, and `.tax/` with
  `README.md`, `master/`, `logs/` by day and `templates/`. No period
  directories: periods are date ranges over the logs, and the FIFO
  ledger is replayed from them.
- `.taxignore` at the data root, one relative path per line, created
  empty by `init`. The file and the paths it names are left out of seals;
  listing a path is the same as keeping the file outside the business
  directory. Exact paths only; no globs until someone needs them.

## Phase 2: hand-over and housekeeping
- `export csv` in the consultant's two-table layout; `export euer`;
  `export fifo`.
- `export gobd`: CSV plus `index.xml` validated against the GDPdU DTD.
- `checkpoint`, `archive`, `expire`, `gc`, `checkout`, `diff`, `log`.
- `seal collect`, `seal attach`.

## Phase 3: e-invoices
- `invoice render ID`: from an `invoice` event and the counterparty's
  master data, produce the human PDF and the structured XML (XRechnung, or
  ZUGFeRD as PDF/A-3 with the XML embedded).
- Validate locally before storing: schema plus the German business rules
  (Schematron). Candidates: Mustangproject CLI for generation and validation,
  or the KoSIT validator for validation only. Both need a Java runtime, which
  becomes an optional dependency of this phase only. Pure-Python libraries
  (factur-x, drafthorse) can generate but validate against the schema only.
- Store PDF, XML and the text sidecar side by side under `docs/invoices/`, each
  registered as a `document` event and all referenced from the `invoice` event.
  The XML is the legal original for a recipient under the e-invoice obligation
  and must be kept byte-identical.
- Receiving side: `doc add` recognises an incoming XRechnung or ZUGFeRD file,
  validates it, extracts its text into the sidecar.

## Later
- Textual terminal UI over the same library functions.
- Rate fetching (`rate SOURCE DATE`) with evidence files saved automatically.
- `verify --backup PATH` and `backup --check`.
