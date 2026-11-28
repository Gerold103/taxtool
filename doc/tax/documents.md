# Documents

A document is a named entry made of one or more files that belong
together as evidence: an invoice as received, a text explaining it, an
e-invoice XML that came with it, a delivery note. The entry is what
events and master data refer to. Its files are immutable; the entry is
created once, with all its files, and removed only as a whole.

Documents are not invoices. An invoice is a business event with amounts
and parties, defined separately; it refers to documents, and a document
may hold an e-invoice XML without being an invoice.

## Entry and files

An entry is named `documents/<YYYY>/<MM>/<DD>/<name>`: the type prefix,
the local day on which the owner added it, and a name. The name has 1 to
63 characters from `a-z`, `0-9` and `-`, starts with a letter and does
not end with a hyphen. It is derived from the first file's name,
lowercased, every run of other characters replaced by one hyphen and the
result trimmed to these rules, unless `--name` gives it. Within one day
names are unique; a derived name that is taken gets `-2`, `-3` and so on.
The full entry name is what logs and master data use, never a shorter
form. Nothing on disk is named after an entry; the entry exists in the
log.

The files of an entry are the owner's files, at the paths where the owner
keeps them. Each has a type:

    blob        a file of the document as received, any format
    txt         the text explaining or transcribing the document, UTF-8
    xrechnung   an e-invoice XML, bytes unchanged

An entry has any number of `blob` files and at most one of each other
type. Further types are added as they are needed; each is defined here
with the option that adds it.

A document's content is fixed by the seal that follows its event: the
seal's tree lists each file's path with the hash of its bytes, and the
seal stores those bytes in the vault's object store, as it does for every
file it lists, so the content survives whatever the owner later does with
the file. To read a document, follow its `document-added` event to the
paths, the log file holding the event to the first seal whose tree lists
that log, the seal's tree to the hashes, and the hashes to the bytes in
the store or to the file wherever it lies today.

## The stage

Changes to the owner's files since the last seal are classified before
they are sealed. The classifications are the stage, whose state on disk
is `.tax/stage.yaml`: `tax add` and `tax rm` read it, add or change an
entry and write it back, `tax reset` removes entries from it. It is a
mutable state, not a log; the logs are written by `tax seal` alone, which
turns the stage into the events of one log file, so changing one's mind
before the seal costs nothing. For every staged file the stage records
the path and the digest of the file at the moment of staging.

`tax status` reads the vault's changes and the stage, not the logs, and
shows every change in one of three groups: staged, with its entry;
unclassified; and staged but changed since, for a file whose digest no
longer matches the stage. It also shows the vault's own events since the
last seal, such as a proof completed or an authority added, which are
not the owner's changes and need no classification.

`tax seal` refuses while any staged file has changed since staging. It
then turns the stage into events: `document-added` for each staged
document, `document-removed` for each staged removal, and a generic
`file-added`, `file-changed` or `file-deleted` with the path for every
owner's file change still unclassified, so the log explains every change
at least generically. It writes them as one new log file, complete, by
writing to a temporary name and renaming into place, and asks the vault
to seal: the vault scans, stores the bytes of every listed file and the
tree objects, and writes the record and the proofs. Only after the seal
succeeds is the stage emptied, so no tree ever lists `stage.yaml` and a
seal that fails loses nothing staged.

Between seals, `.tax/logs/` changes only through `tax seal`, and each
log file is listed as new by exactly one seal and never changes. So the
vault's report of changes since the last seal must show nothing under
`.tax/logs/`, and anything it shows there is a failure state: a log file
not listed by the last seal is a seal that did not complete, after a
crash or after no authority accepted the root; a listed log file that
changed or disappeared is tampering. `tax status` reports the state
before anything else, and `tax add`, `tax rm` and `tax seal` refuse while
it stands. It is resolved by `tax reset --hard`, which removes the
unlisted file and restores the listed ones from the store, or by the
owner deleting the unlisted file by hand, after which the stage, still
intact, can be sealed again.

## Events

Events are actions. Every event carries `type` and `time`, the time it
was recorded, as the local clock time with its offset. These are the
event types defined so far.

    - type: document-added
      time: '2026-11-30 18:02:11+01:00'
      entry: documents/2026/11/27/telekom-invoice
      files:
      - path: Rechnungen/2026/telekom-11.pdf
        type: blob
      - path: Rechnungen/2026/telekom-11.txt
        type: txt

    - type: document-removed
      time: '2026-12-01 08:30:00+01:00'
      entry: documents/2026/11/27/telekom-invoice
      why: added twice by mistake

    - type: file-added
      time: '2026-11-30 18:02:11+01:00'
      path: Vertraege/buero-2027.pdf

    - type: file-changed
      time: '2026-11-30 18:02:11+01:00'
      path: notes.xlsx

    - type: file-deleted
      time: '2026-11-30 18:02:11+01:00'
      path: alt/entwurf.docx

`document-added` lists every file with its path relative to the data
root at the moment of addition and its type. The day in the entry is the
day of `tax add`; the event's time is when `seal` wrote it. The generic
file events record the owner's changes that no classification explained;
they carry the path and nothing else, since the seal's tree holds the
hashes.

## Lifecycle

An entry exists from `document-added` on and is void from
`document-removed` on. It is removed only as a whole and only when
nothing refers to it: no event in any log names it other than its own
`document-added`, and no master data entry names it. Removal exists for
mistakes, a document added twice or to the wrong business. `tax rm
document` checks the references when staging and `tax seal` checks them
again before executing. Removal writes the event and nothing else; the
files' bytes stay in the store for as long as a seal's tree lists the
files, which is until those seals expire, as `doc/vault/layout.md`
describes under garbage collection.

## Commands

    tax add document -f FILE [-f FILE ...] [--txt FILE] [--xrechnung FILE]
                     [--name NAME]

Stages one document entry. Every FILE is a path inside the data root.
Each `-f` adds a file of type `blob`; `--txt` and `--xrechnung` add the
file of that type, at most one each. The entry name is derived from the
first `-f` file unless `--name` gives it. The command prints the entry
name and its files; the entry name is fixed from this moment, so other
staged entries can refer to it before the seal. A file already staged in
another entry is refused.

    tax rm document ENTRY --why TEXT

Stages the removal of an entry, refused if anything refers to it, and
prints what does.

    tax reset [PATH ...]

Removes the staged classification of the given paths, or of everything.
The files themselves are untouched.

    tax reset --hard

Returns the business directory to the state of the last seal. Every file
the seal's tree lists is restored to the bytes the store holds for it,
whether it was edited or deleted since; log files the tree does not list
are deleted; the stage is emptied. Owner's files the tree does not list
are left where they are, staged or not, and become unclassified changes:
`git reset --hard` would delete the staged ones, but git already holds
their bytes when they are staged and we do not, so deleting them would
lose them. The state at an older seal is not restored in place, since
that would delete logs that later seals sealed; it is read with
`checkout`, into a separate directory.

    tax status

Prints the failure state, if anything under `.tax/logs/` differs from
the last seal; otherwise the staged entries with their files, the files
staged but changed since,
the unclassified changes with the vault's kind of change, added, changed,
appended or deleted, and the vault's own events since the last seal.

    tax doc list [--since DATE]
    tax doc show ENTRY
    tax doc export ENTRY [DIR]

Read-only views over the logs and the vault: every entry with its files;
one entry with its files, their sizes, the seal that covers it, and the
events and master data that refer to it; and the files of one entry
written into DIR under their file names from the bytes in the store, by
default a directory named after the entry.
