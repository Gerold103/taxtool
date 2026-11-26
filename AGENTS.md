## taxtool

Guidance for agents working in this repository. People should start with
`README.md`; this file holds the details an agent needs to act correctly.
`CLAUDE.md` is a symlink to this file.

taxtool is local, open-source bookkeeping for small German businesses,
Freiberufler and Gewerbe alike. The first target is the EÜR profit method
with a Kleinunternehmer; VAT and other regimes come later and should need
additions, not rewrites, so tax-regime assumptions stay out of the storage
layer and behind explicit configuration in the application layer.

Mechanics: append-only YAML logs of typed events, content-addressed storage
of original documents, periodic seals whose root hash is timestamped by
external RFC 3161 authorities and chained to the previous seal. Target
properties: GoBD-style immutability that is verifiable offline with
standard tools, no cloud, no bank linking, minimal dependencies, data
readable without the tool.

### Structure

The project values simplicity and verifiability over everything else.
Performance matters only where something is measured to be both massive
and slow.

The language is Python 3.13 with asyncio for all IO. Dependencies are kept
to `pyyaml` and `aiohttp` at runtime.

```
tax, test.sh, check.sh   entry scripts; they create and enter .venv
pyproject.toml           ruff, mypy, pytest configuration; line-length 80
src/vault/               storage layer, no tax knowledge
src/taxtool/             application layer on top of vault
test/                    pytest suite mirroring src/
doc/agents/              task-specific guidance, see below
doc/risks.md             what seals prove and every known way around them
sandbox/                 scratch, ignored by git; sandbox/var/ for temp
ROADMAP.md               agreed design and phases
```

`src/vault/` knows bytes, paths, hashes, manifests, seals and proofs, and
must not import from or know about `src/taxtool/`. `src/taxtool/` owns
events, logs, periods, the FIFO ledger and the command line.

The data directory a user works in is not in this repository. Its layout:
a `.tax/` directory owned by taxtool, next to `config.yaml`,
`master.yaml`, `log/`, `docs/`, `periods/` and `templates/`. Inside it,
`.tax/.vault/` is owned by the vault: the object store, seals and proofs,
authority configuration and material, the stat cache. `ROADMAP.md`
describes it; a generated example data set will return to the repository
once the tool can produce it.

### Working here

- Run `./check.sh` (ruff format, ruff check, mypy strict, pytest) before
  declaring a change done. Report failures verbatim.
- Every text file wraps at 80 columns, including Markdown, YAML and these
  documents.
- Commit only when the user asks. Never `git add -A`.
- Temporary files go under `sandbox/var/`; pytest puts `tmp_path` there.
- The design was discussed at length before coding. When a design question
  comes up, check `ROADMAP.md` first; if it is silent, ask rather than
  invent, and record the answer there.
- A change that alters what can be proven, forged or lost must update
  `doc/risks.md` in the same commit. The document is written for an
  auditor and is deliberately candid.
- Python is 3.13 from MacPorts (`/opt/local/bin/python3`). The system
  `/usr/bin/python3` is 3.9 and must not be used.

### Domain notes that affect code

- Money is `Decimal`, two places for EUR amounts, rates kept at source
  precision. Never float.
- Dates are ISO `YYYY-MM-DD` strings in data files; times in seals are
  UTC ISO 8601 with offset.
- Hashes are lowercase hex SHA-256. Blob paths are `objects/ab/cdef...`.
- Logs are append-only. The tool appends; it never rewrites a log. A seal
  marker event in a log records the sealed prefix length and hash so the
  sealed part can be re-derived by truncation.
- Corrections are new events with `supersedes`; nothing is edited.

### Task-specific guidance

The files under `doc/agents/` hold deeper, task-specific knowledge, the
agent-agnostic equivalent of Claude Code "skills". Each has a description
below.

**Do not read these files up front.** Load a file into context only once
your current task matches its description, and only the one(s) that match.
You can make this decision without opening the files first, by looking at
the descriptions here.

- `doc/agents/python-style.md` - Code style and architecture rules for
  this repository. Use whenever writing, editing, reviewing or refactoring
  any Python or text file, even for a one-line fix.

- `doc/agents/commits.md` - How to split work into commits and write
  commit messages here. Use whenever committing, staging, amending,
  squashing or reviewing history.

- `doc/agents/testing.md` - How tests are written and run here. Use
  whenever adding or changing tests or fixtures, running the suite, or
  deciding how to test IO.

These descriptions are copied from the `description` field of the matching
Claude skill files in `.claude/skills/*/SKILL.md`. If at some point you
open one such skill file and notice its description differs from the copy
above, it must be flagged to the user.

---

If anything in this overview seems wrong, overly restrictive or outdated
from how the code actually works, it must be flagged to the user with a
proposed improvement instead of being silently worked around.
