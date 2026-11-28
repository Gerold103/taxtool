# Layout of the vault's home

The vault receives two directories: the data root, whose files it seals,
and its home inside the data root, where it keeps everything it writes.
In a business directory the home is `.tax/.vault/`; the vault does not
know that name. The vault is a library; the commands that drive it belong
to the application.

    <home>/
      objects/<ab>/<cdef...>          content-addressed blobs
      seals/<NNNNNN>/seal.yaml        seal record
      seals/<NNNNNN>/proof/<authority>/   one proof per authority asked
      authorities/<name>/authority.yaml   type, settings, enabled flag
      authorities/<name>/<material>   key, certificate chain
      cache                           stat cache of the last scan

The vault works with three kinds of things. A blob is a piece of content
stored under its own hash. A tree object is a blob that lists one
directory of the data root, so that one hash stands for every file below
it. A seal is a signed statement that the data root had a given root tree
at a given time. The sections below define each in turn, then the
authorities that sign, the changes the vault reports, and garbage
collection.

## The object store

`objects/` is the content-addressed store. A blob lives at
`objects/<ab>/<cdef...>`, the first two hex digits of its SHA-256 as the
directory and the remaining sixty-two as the file name, and is read-only.
The file holds the content's bytes exactly as hashed, with no header, no
compression and no metadata, so `sha256sum` on the file prints the
directory name and the file name joined, which is how anyone checks a
blob without the tool. What the bytes are is a property of whatever
names the blob, not of the blob: a file of the data root through a tree
entry of kind `file`, a tree object through a tree entry of kind `tree`.
Writing is atomic: the content goes to a temporary file that is renamed
into place, so a crash never leaves a half blob under a valid name.
Storing content whose blob already exists re-reads that blob; if it no
longer hashes to its name the store reports it corrupt, and if it is
intact but differs from the new content the store reports a hash
collision and keeps the blob it has.

The store holds two kinds of content and does not distinguish them: the
bytes of every file a seal lists, and the tree objects that list them.
Sealing stores both: for each file in the tree whose hash is not in the
store, a copy of its bytes goes in, deduplicated by hash. So the store
holds every version of every file that was ever sealed, and the state of
the data root at any seal can be rebuilt from the store and that seal's
tree alone. A file's content survives whatever the owner later does with
the file, and it is found through the hash that a seal's tree lists for
the file's path. The store is therefore a full copy of the business
directory plus the past versions of changed files; losing it loses the
copies and the tree objects, but no proof, since every hash is in the
seal records and their trees. The vault's own files are no exception:
earlier seal records and proofs and the authority directories are listed
and stored like the caller's files. That includes an authority's secret
key, which therefore exists as the file and as a read-only blob, both
under the home, and stays in the store for as long as a seal lists the
file, which is for good.

Reading a file as it was at a seal means following the seal's tree to
the file's hash and taking the blob from the store. If the store lacks
the blob, the file at the same path in the data root is taken instead,
provided it still hashes to the listed value; otherwise the file's bytes
at that seal are lost and the vault reports that. Verification reads an
authority's material this way, and the application's export and
checkout read documents and whole seals this way.

Blobs are not listed in any seal's tree, yet a seal commits to their
content: a file's copy through the tree entry for its path, and a tree
object through the parent listing that names it, up to the root in the
seal record. A tree entry for a blob would only repeat the hash that is
its name. The one kind of blob no seal commits to is an orphan that
nothing names, and that is exactly what garbage collection removes.

## Tree objects

A tree object is the YAML listing of one directory of the data root. Each
entry is a name with the kind of thing it names, a file or another tree,
and the SHA-256 and size of that thing's bytes: for a file, the file's
content; for a tree, the child listing's YAML.

    entries:
      2026:
        kind: tree
        sha256: 5e1a...
        size: 212
      readme.txt:
        kind: file
        sha256: 9f86...
        size: 1
    version: 1

Entries are sorted by name and the YAML is deterministic, so the same
directory contents always produce the same object. The listing is stored
in the object store like any blob, and the root listing's digest stands
for the whole data root: from it, every file is reached through the
listings on its path, each verified against the hash its parent recorded.

Between two seals only the directories on the path to a changed file get
a new listing. Every unchanged subtree keeps its hash and is the same
object in the store, shared by both seals. A directory that never
changes again costs one entry in its parent's listing per seal, however
large it is. A subtree together with the listings on its path to the
root is a self-contained proof of that subtree, which can be handed over
on its own.

## Seals

`seals/<NNNNNN>/` is one seal, numbered from `000001` in six digits so
that directories sort. `seal.yaml` is the record:

    version: 1
    id: 3
    time: '2026-11-27T10:00:00+00:00'
    tree:
      sha256: <root tree object>
      size: <its size in bytes>
    previous: <sha256 of seal 2's seal.yaml, or null for seal 1>
    authorities:
    - local
    - ots

`tree` names the root tree object of the data root as scanned at that
moment. `previous` names the hash of the previous seal's record, so the
seals form one chain. `authorities` names every authority asked, so that
a missing proof is a finding and not an unknown. The SHA-256 of the
record's bytes is the root hash the authorities stamp, so one proof
covers the tree, the time and the chain link. The record is written
read-only and never changed. Its time is UTC, since it is for the
authorities.

A seal's tree lists every regular file under the data root except
`objects/` and `cache` in the home, the paths the caller excludes, and
the seal's own directory, which does not exist when the tree is written
and which the next seal is the first to cover. Symbolic links and special
files are errors. The newest seal is therefore protected by its proofs
alone; every older seal, every authority directory and every file of the
caller is protected by the tree of the seal after it, and every blob by
the tree entry or tree object that names it.

Creating a seal asks every enabled authority and requires at least one
to accept the root hash, complete or pending; if none does, the seal
directory is removed again and the error names every failure, so no seal
exists without a proof attempt behind it.

`seals/<NNNNNN>/proof/<authority>/` holds what the named authority wrote,
one directory per name in the record's `authorities`. By type:
`local-hmac-sha256` writes `token.yaml`; `rfc3161` writes `request.tsq`
and `token.tsr`; `opentimestamps` writes `stamp.yaml` and
`root.pending.ots` at sealing, then `root.ots` and `block-header.bin`
when the proof completes. `abandoned.yaml`, with `time` and `why`, marks
a proof the owner gave up; a proof so marked is reported as abandoned and
not asked again. Files are added to a proof directory, never rewritten or
removed.

## Authorities

`authorities/<name>/` is one authority, named by its directory, the name
being one path component. `authority.yaml` holds `type`, `enabled` and
the settings of that type:

    type: rfc3161
    enabled: true
    url: https://freetsa.org/tsr

The material next to it depends on the type: `local-hmac-sha256` has
`key`, the hex-encoded secret of at least 32 bytes, and no settings;
`rfc3161` has `chain.pem`, the authority's certificate chain, and the
setting `url`; `opentimestamps` has no material and the settings
`calendar` and `explorer`. `enabled` defaults to true when absent.

The directory serves new work only. Creating a seal asks every enabled
authority in it, and completing a pending proof takes the explorer from
it, while the calendar comes from the pending attestation inside the
proof file. Verification never reads the directory: for a proof of seal
N it takes the authority's `authority.yaml` and material from the tree of
seal N, through the store, so a proof is verified with the type, key and
certificate chain that were in force when it was made. A rotated key or
a renewed chain leaves every older proof verifiable against its own
material. An authority is retired for new seals by setting `enabled:
false`, or by deleting its directory, which the next seal records as an
authority removed and which makes nothing unverifiable.

## The stat cache

`cache` holds, for every file of the last scan, its size, modification
time and hash, so that an unchanged file is not hashed again. It is
derived data: deleting it costs one full scan and changes nothing else.
No seal covers it.

## Changes since a seal

The vault reports what differs between the newest seal's tree and the
data root as events, one per changed path. For a change inside its own
home it knows what the change means; for everything else it reports the
fact about the file and the application decides what it means.

    seal added, removed, tampered            seals/<NNNNNN>/seal.yaml
    proof completed, abandoned, tampered     seals/<NNNNNN>/proof/<authority>/
    authority added, changed, removed        authorities/<name>/
    file added, appended, changed, deleted   any other path

A seal, proof or authority event names the seal id, the authority name or
both. The newest seal's own directory is left out of the comparison, as
the HEAD commit is left out of `git status`: its record and proofs are
the seal, not changes to it. Its proofs are reported by verification
instead.

Verification checks every seal and reports findings about the whole: a
seal directory missing, a record unreadable or naming the wrong id, a
chain link whose `previous` does not match the record before it, a tree
object missing or corrupt; and for every proof what the authority's type
and material, read from that seal's own tree, say about it offline:
complete with its time, pending, abandoned, or failed with the reason,
which includes material that the tree lists but that neither the store
nor the data root can produce.

## Garbage collection

Garbage collection deletes blobs that nothing needs. It keeps a blob if
either holds, and deletes it otherwise:

- a tree object reachable from any seal's root is the blob;
- a file listed in any seal's tree has the blob's hash, so that a file's
  bytes stay as long as a seal names that file.

Everything else in the store is an orphan that no seal commits to. Seal
directories and authority directories are never touched by garbage
collection; a seal leaves through the application's expiry of its
retention, which is a separate operation.
