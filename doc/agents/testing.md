# Testing in taxtool

This document explains how tests are written and run. Tests are the only
proof the tool does what the design says, and the design is about data
that must survive an audit years later. So tests exercise the real code
paths against real files and real sockets, never a stand-in.

## Coverage

Each changed line, unless it is a simple refactoring like a rename or a
code move, must be covered by tests. Sometimes older tests already cover
the place implicitly; much more often new tests are needed. Every error
path the code has gets a test that triggers it for real (corrupt a byte,
delete a blob, truncate a log) and checks the message says what an
operator needs.

## Layout

Tests live in `test/`, mirroring the package layout of `src/`: one test
module per source module, in a subdirectory per package. `conftest.py`
holds shared fixtures only. Cross-cutting checks such as the import graph
sit at the top of `test/`. Helpers used by more than one test module, and
committed fixture files, live in the `test/support` package and are
imported as `support.<module>`; test directories themselves are not
packages.

`./test.sh` enters the venv and runs `pytest test/ "$@"`. Pass a path or
`-k name` to narrow. Configuration lives in `[tool.pytest.ini_options]` in
`pyproject.toml`: `testpaths`, `pythonpath = ["src", "test"]`,
`asyncio_mode = "auto"`, and `--basetemp=sandbox/var/pytest`.

## Never mock

No `unittest.mock`, no monkeypatching of library internals, no fake
classes that imitate a dependency. A mock tests that the code calls what
you expected it to call, which is the one thing a refactor is allowed to
change; it tells you nothing about whether the result is right. Instead:

- Network: start a real server in the test process on `127.0.0.1:0` with
  `asyncio.start_server` or an `aiohttp.web` app, point the code at its
  port, assert on what the server received and what the client got back.
  An RFC 3161 test runs a tiny HTTP handler that returns a prepared
  `.tsr` file.
- Subprocesses: run the real binary (`openssl`), skip with `pytest.skip`
  only if it is genuinely absent on the machine, and say so.
- Filesystem: real directories under `tmp_path`.
- Time: pass the clock in as a parameter (`now: datetime`) rather than
  patching `datetime`. Code that needs the current time takes it from the
  caller; the CLI supplies `datetime.now(UTC)`.
- Randomness and keys: generate real ones in the fixture; tests do not
  need fixed values when they assert on properties and round trips.

If something cannot be tested without a mock, the code has a hidden
dependency; make it a parameter and test it for real.

## Temporary files

Use pytest's `tmp_path` and `tmp_path_factory`. Because of `--basetemp`,
they resolve under `sandbox/var/pytest/`, which is ignored by git and safe
to delete at any time. Never write into the repository tree, `/tmp`, or
the user's home from a test. A test that must inspect what was left behind
can print the `tmp_path`; pytest keeps the last three runs.

## Async tests

`asyncio_mode = "auto"` means an `async def test_*` runs on a fresh event
loop with no decorator. Fixtures that need the loop are `async def` too.
Never call `asyncio.run` inside a test; never block the loop with sync
sleeps or sync sockets.

## What a good test looks like

- One behaviour per test, named for the behaviour:
  `test_appended_log_verifies_by_prefix`, not `test_manifest_2`.
- Arrange, act, assert, in that order, with no branching. Parametrise with
  `pytest.mark.parametrize` instead of looping inside the test.
- Assert on outcomes a user or auditor would care about: file contents,
  hashes, returned problems, exit codes. Not on internal call order.
- Round trips are the cheapest strong test: dump then load, seal then
  verify, hash on disk then hash from the manifest.
- Tests are typed and formatted like all other code; `mypy --strict` and
  `ruff` run over `test/` too.

## Fixtures

Keep fixtures few and literal. A fixture that builds a small initialised
repository with a local authority is fine; a fixture that takes options
to produce ten variants is a test framework in disguise. Prefer a plain
helper function in the test module when a fixture would need parameters.

---

If anything in this document seems wrong, overly restrictive or outdated
from how the code actually works, it must be flagged to the user with a
proposed improvement instead of being silently worked around.
