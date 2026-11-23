# Commits in taxtool

This document explains how work is split into commits and how commit
messages are written. The history is part of the audit trail of the tool
itself, so each commit should be a unit a reviewer can read, understand and
revert on its own.

## Atomic commits

Work is always organised as a sequence of atomic commits: commits that are
fully self-sufficient and bring value on their own. Each commit must be
such that nothing can be removed from it without making it lose its sense,
and nothing needs to be added to make it valuable and working.

In practice: a new function with its tests, a rename, a bug fix with the
regression test. Not "vault work" with five unrelated edits, and not a fix
split from the test that proves it. If a change needs preparatory
refactoring, that refactoring is its own commit first.

Each commit must pass `./check.sh` (format, lint, types, tests) on its own,
so `git bisect` stays usable at every point of the history.

## Title

The title has the format `system: imperative title`, for example
`seal: record hashes of previous proofs`. It is limited to 50 characters.
That is a soft limit, exceeded only when genuinely impossible; it is what
`git log --oneline`, GitHub and email subjects show untruncated.

`system` is the module or block the commit is about. Reuse an existing
short name; do not invent a new one for every file. Current vocabulary:

```
vault  hashing  objects  manifest  tree  cache  seal  authority  bitcoin
taxtool  events  log  periods  ledger  cli
test  docs  build
```

Add a name only when a new module appears, and add it to this list in the
same commit. The title after the colon is imperative, lowercase, no
trailing period: "add prefix hash for append-only files", not "Added prefix
hashing" or "prefix hashing.".

## Body

The body is descriptive, not narrative. It explains the reason for the
change: the problem, the alternative that was rejected and why, the
constraint that forced the shape. It does not narrate the diff, which the
reader already has. For highly complex changes a general outline of what is
done is fine, after the why.

Lines are limited to 72 characters. This is strict for prose; it may be
exceeded only for listings that cannot be wrapped, such as a long link.
Separate the title from the body with a blank line, and split the body into
short paragraphs, one thought each. A trivial commit may have no body; a
non-obvious one must have one.

Reference design decisions by pointing at `DESIGN.md` sections rather than
re-explaining them. Never paste command output or file listings.

Title, body and diff use ASCII characters only, unless something explicitly
requires otherwise, such as test data with an umlaut.

## Tests travel with the code

A commit that adds or changes behaviour includes the tests for it in the
same commit. A pure refactor already covered by existing tests is the one
case with no test changes, and the body says so in a sentence. A change
that cannot be tested without a mock is shaped wrong; see
`doc/agents/testing.md`. Pure refactors keep the existing tests passing
without edits, which is how a reviewer knows they are refactors.

## Example

```
seal: record hashes of previous proofs

A seal's `previous` only covered the previous root.yaml, so the
timestamp tokens themselves were never re-stamped and would have
to stand on their own after their signing certificate expired.

Recording the sha256 of each previous proof file in the new seal
makes every new token cover the old ones, which gives long-term
validity for free as long as sealing continues. Verification now
checks this field when it is present, so older examples still pass.
```

## Mechanics

- Commit only when the user asks. Stage specific files, never `git add -A`
  blindly; check `git status` first for stray files such as `sandbox/`.
- Before the first commit in a session, ask the user whether commits
  should carry a `Co-Authored-By` trailer for the agent, unless a memory
  about this project already answers that. Whatever the answer, it holds
  for the whole project until the user says otherwise.
- No emoji, no ticket prefixes.
- Do not amend or rewrite commits that have been pushed. Local history may
  be squashed to keep the atomic story before a push. Fixups are squashed
  into the commit they fix, never stacked on top.

---

If anything in this document seems wrong, overly restrictive or outdated
from how the code actually works, it must be flagged to the user with a
proposed improvement instead of being silently worked around.
