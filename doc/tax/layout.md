# Layout of a business directory

One directory holds everything about one business. The owner's files live
in it in any layout the owner likes. taxtool adds exactly two entries at
the top level, `.taxignore` and `.tax/`, and writes nowhere else. Inside
`.tax/`, the directory `.vault/` is the vault's home, described in
`doc/vault/layout.md`; the vault receives the data root and this home as
parameters and knows neither the name `.tax` nor taxes.

    my_business/                          data root
      <anything>                          the owner's files, any layout
      .taxignore                          paths left out of seals
      .tax/                               written by taxtool
        README.md                         what this directory is
        master/business.yaml              the business, regime, time zone
        master/counterparties.yaml        customers and suppliers
        master/accounts.yaml              payment accounts
        logs/<YYYY>/<MM>/<DD>/log_<NNNNNN>.yaml   event logs
        templates/<event-type>.yaml       blank events for manual entry
        stage.yaml                        classifications awaiting a seal
        .vault/                           the vault's home

## The owner's files

Any file or directory not named here belongs to the owner: documents,
contracts, spreadsheets, in whatever arrangement and under whatever names
the owner chooses. taxtool prescribes nothing about them and reads an
owner's file only when asked to add it as a document, see
`doc/tax/documents.md`. Every seal fixes the hash of every owner's file,
so a changed contract is as visible as a changed log.

`.taxignore` lists paths relative to the data root, one per line, exact
paths without globs. A listed file, or a listed directory with everything
below it, is left out of seals, and so is `.taxignore` itself, since a
sealed exclusion list would fix the names of the excluded things in every
seal. Listing a path is the same as keeping the file outside the business
directory, a convenience for files the owner wants nearby but not
tracked. `init` creates the file empty.

## taxtool's files

Everything taxtool writes is under `.tax/`, and all of it is sealed.

`README.md` is one page for a person who opens the folder without the
tool: what the directories hold and how to verify a seal with standard
tools. `init` writes it.

`master/` holds master data, one YAML file per kind: `business.yaml` for
the business itself, `counterparties.yaml` for customers and suppliers by
id, `accounts.yaml` for payment accounts by id. `doc/tax/master.md`
defines every field. A further kind of master data gets a further file.
Master data is edited in place by the owner and validated by `tax check`;
an edit shows as a changed file at the next seal.

Every date and time taxtool writes for the owner is local to the
business's time zone: the day in a log path or a document entry, and
every `time` in a log, which is written as the local clock time followed
by its offset from UTC, as in `2026-11-30 18:02:11+01:00`, so that a
person reads the time as it was on the clock and a machine needs no zone
to interpret it. Changing the zone later changes nothing already written.
The vault's own seal records keep UTC, since their time is for the
authorities.

`logs/` holds the event logs, one file per seal. `tax seal` writes the
events it records as one file at `logs/<YYYY>/<MM>/<DD>/log_<NNNNNN>.yaml`,
where the date is the local day of the seal and `<NNNNNN>` counts the
files written on that day from `000001`, and seals immediately after. A
log file is complete when it appears and never changes afterwards; it is
listed as a new file by the seal that follows it, and that seal is the one
that covers it. A seal that records no events writes no log. An event is
an action, something added, changed or removed, and carries the time at
which it was recorded. Each directory on the path holds at most one entry
per day, month or year, so no listing grows with the number of events.
The event types are defined with the things they act on;
`doc/tax/documents.md` defines the first of them and the generic file
events.

`templates/` holds one blank event per event type, for the owner to copy
and fill in when entering an event by hand.

`stage.yaml` is the on-disk state of the stage: the owner's
classifications of the changes since the last seal, as they stand now.
`tax add`, `tax rm` and `tax reset` each read it, change it and write it
back; it is a state, not a log, and nothing in it is final until `tax
seal` turns it into the events of one log file and empties it;
`doc/tax/documents.md` describes the loop. No tree ever lists it.

## Ownership and what a seal covers

Outside `.tax/` the owner owns everything. Inside `.tax/` taxtool owns
everything, and inside `.tax/.vault/` the vault does. The contents of
`.tax/` are meant to be viewed and changed through the command line; the
master files are edited by hand until the commands for them exist.

A seal's tree lists every regular file under the data root except the
vault's object store, whose blobs the seal commits to by hash instead,
the vault's stat cache, `.taxignore` and the paths it names, `stage.yaml`,
which `tax seal` empties before it scans, and the seal's own directory,
which the next seal is the first to cover. The vault's side of this is in
`doc/vault/layout.md`.
