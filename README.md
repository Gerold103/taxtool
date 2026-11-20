# taxtool

Local bookkeeping for small German businesses, Freiberufler and Gewerbe
alike, built so that an auditor can check years later that nothing was
changed after the fact. It starts with the EÜR profit method; VAT and
further regimes are planned as additions.

The idea is simple. Every business event (an invoice, a payment, a currency
conversion, an expense) is one entry appended to a plain YAML log. Every
document (invoice, bank statement, receipt) is stored once, exactly as
received, with a text copy next to it and its SHA-256 hash in the log.
From time to time you `seal`: the tool hashes everything into one root hash
and asks independent timestamp authorities (RFC 3161) to sign it. Each seal
references the previous one, so the whole history is a chain. Anyone with
the folder and standard tools such as `openssl` can verify it offline.

No cloud, no accounts, no bank linking, no proprietary formats. Your data is
a directory of text files and originals you can read without this tool.

What a seal proves and what it cannot, including every known way the
records could still be wrong, is written down in `doc/risks.md`.

## Status

Early development. The data layout is settled; the tool that produces and
verifies it is being written. See `ROADMAP.md` for what comes when.

## Requirements

- macOS or Linux
- Python 3.13 or newer
- `openssl` with timestamp support, for real RFC 3161 seals

## Getting started

```bash
git clone <this repository> taxtool
cd taxtool
./tax --help        # creates .venv on first run
./test.sh           # runs the test suite
```

The data directory is separate from the repository. `tax init
~/my_taxes` creates one; afterwards run `tax` from anywhere inside it, the
way you would run `git`.

## Repository layout

- `src/vault/` the storage layer: hashes, content-addressed blobs,
  manifests, seals and proofs. Independent of any tax logic.
- `src/taxtool/` the application: event types, logs, periods, FIFO ledger,
  command line.
- `test/` pytest suite.
- `ROADMAP.md`, `DESIGN.md` plans and the agreed design.
- `doc/agents/` contributor rules for code style, tests and commits,
  written for coding agents but equally valid for people. `AGENTS.md` is
  the entry point.

## Licence

To be decided before the first release.
