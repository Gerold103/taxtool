# Code style in taxtool

This document explains how code is written in this repository: formatting,
typing, imports, modularity, IO, comments, and the simplicity bar. The tool
is meant to be read by auditors and strangers years from now, so the code
optimises for being obviously correct over being clever. Everything below
follows from that.

## Formatting: ruff, 80 columns

`ruff format` is the black-compatible formatter; `ruff check` runs the
flake8, isort and pyupgrade rule sets. Both read `[tool.ruff]` in
`pyproject.toml`, where `line-length = 80`. Never hand-format against the
tool: run it, then commit what it produced.

```bash
ruff format src test
ruff check --fix src test
mypy
```

`./check.sh` runs all three plus the tests; run it before every commit.
Eighty columns is deliberate: diffs, side-by-side review and terminal UIs
all fit. If a line does not fit, the expression is usually too dense;
extract a name instead of fighting the formatter.

## Typing: mypy strict, everywhere

Every function signature is annotated, including tests and `-> None`.
`mypy --strict` must pass with zero errors; `# type: ignore` needs a reason
in the same comment and should be rare enough to list by hand. Prefer
precise types over `Any`: `Mapping[str, FileEntry]`, not `dict`. Use
`dataclass(frozen=True)` for records and `Protocol` for pluggable parts such
as authorities. Python target is 3.13, so write modern syntax: `X | None`,
`list[str]`, `type` statements, `match` where it reads better.

## Imports: top of file, no cycles

All imports sit at the top of the module, grouped stdlib / third-party /
local, sorted by ruff. No imports inside functions, no `TYPE_CHECKING`
tricks to dodge a cycle. A cycle is not a packaging problem to work around;
it means two modules each need something the other owns, so the ownership
is wrong. Fix it by moving the shared piece into a lower module or by
inverting the dependency. Layers depend downwards only: `taxtool` imports
`vault`, never the reverse. A test builds the import graph of `src/` with
`ast` and fails on any cycle, so a bad design shows up as a red test rather
than a runtime surprise.

## Modularity

Code must be modular. A new function goes exactly where it belongs, and
stays private to its module (underscore prefix, not exported) unless it is
genuinely needed elsewhere. When a function's scope changes, move it to the
module that now owns it. Modularity matters because it keeps the cognitive
load low: one can work on sealing without knowing how periods work, and an
auditor can read the storage layer without reading tax law.

`vault` knows bytes, paths, hashes, manifests, seals and proofs. It must
not know what an event, a period, an invoice or a tax year is, nor the
name of the directory it is stored in. If a change to `vault` needs an
application concept, the concept belongs in `taxtool` and `vault` gets a
plain generic parameter instead, such as a set of paths to exclude or the
directory to write into. Not a predicate or a callback: the vault reports
facts about bytes and paths, and `taxtool` decides what they mean.

Existing code is changed freely when that helps reuse it, and deleted when
superseded. Nothing is kept "for backward compatibility" or "for later",
unless it preserves behaviour visible in a user's data directory.

## Asyncio first, no blocking IO

The library is async from the start because a Textual UI and parallel
timestamp requests come later, and retrofitting async is painful. Rules:

- Public library functions that touch the network, the filesystem or
  subprocesses are `async def`. Pure computation stays sync.
- Network: `aiohttp` for HTTP, with async DNS. No `requests`, no `urllib`.
- Subprocesses such as `openssl ts`: `asyncio.create_subprocess_exec`.
- Filesystem: asyncio has no native file API and `aiofiles` is threads in
  disguise, so wrap reads, writes and hashing in `asyncio.to_thread` and
  keep the sync helper small. Tiny metadata calls like `Path.exists` are
  fine inline. `to_thread` shares the loop's default executor, which the
  CLI caps at two workers; the tool moves a handful of files per session
  and must stay light.
- No `time.sleep`, no synchronous sockets, no blocking calls in the event
  loop. If something truly cannot be async, say so in a comment at the
  call.
- The CLI entry point does `asyncio.run(main())` once; nothing else creates
  loops.

## Simplicity over everything

Pick the plainest construct that works: a function over a class, a tuple
over a new type, stdlib over a dependency, a loop over a comprehension that
needs a second read. Optimise only something measured to be both massive
and slow, and leave a comment with the measurement. No speculative
abstraction, no plugin systems for one implementation, no configuration for
a value that has never needed to change. Delete code that is not used.
Three similar lines beat one premature helper.

## Comments and docstrings

Comments are never narrative. A comment that restates the next lines, talks
about commits or the development plan, or is obvious in any way, must be
deleted. Write a comment only where the code is genuinely complex and needs
context the reader cannot get from the code itself, and then explain why,
not what.

Docstrings follow the same rule: one line, imperative, stating what the
function guarantees, only where the name does not already say it. Public
dataclasses and protocols get a short docstring saying what they represent,
because they are the vocabulary of the module.

## Naming and layout

- Modules and functions `snake_case`, classes `CapWords`, constants
  `UPPER_CASE`. Names say what the thing is, not its type: `manifest`, not
  `manifest_dict`.
- One module, one topic, roughly under 300 lines. Split by topic, not by
  size.
- Errors: raise specific exceptions from a small hierarchy per package
  (`VaultError`, `TaxError`), with messages an end user can act on. Never
  swallow an exception without handling it.
- Paths are `pathlib.Path`, hashes are lowercase hex `str`, money is
  `decimal.Decimal`, times are timezone-aware `datetime` in UTC.
- Source files are ASCII only. Non-ASCII appears solely in test data that
  needs it, such as a German counterparty name with an umlaut.

## Text files

Every text file in the repository, not only code, wraps at 80 columns:
Markdown, YAML, shell scripts, these documents. Hard-wrap prose; break
long URLs onto their own line rather than exceeding the limit. The reason
is the same as for code: everything stays readable in a terminal, in a
diff and side by side.

## Dependencies

Runtime: `pyyaml`, `aiohttp`. Dev: `pytest`, `pytest-asyncio`, `ruff`,
`mypy`. Adding anything else needs a sentence in the commit body on why
the stdlib could not do it.

---

If anything in this document seems wrong, overly restrictive or outdated
from how the code actually works, it must be flagged to the user with a
proposed improvement instead of being silently worked around.
