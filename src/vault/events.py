"""Events: what the changes since the last seal mean.

The scanner reports changes as facts about paths and bytes. This module
names them: a change inside the vault's own home directory is one of the
specific events below, such as a seal added or a proof abandoned, and
anything else is a generic file event the caller interprets by path.

Each event class knows how to make itself from one Change, or declines
with None. `KINDS` lists the classes in the order they are tried, most
specific first, and the first that accepts the change classifies it. A
new event is one class with one `make` and one entry in `KINDS`. Every
`make` states on its own which kinds of change it accepts, so the order
only settles which of several fitting events wins, never whether a class
fits.
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Self

from vault.manifest import check_relpath
from vault.scan import Changes

SEALS_DIR = "seals"
SEAL_FILE = "seal.yaml"
PROOF_DIR = "proof"
ABANDONED_FILE = "abandoned.yaml"


class LazyPattern:
    """A regex compiled on first use, so that importing this module costs
    nothing when no change needs classifying."""

    def __init__(self, source: str) -> None:
        self._source = source
        self._compiled: re.Pattern[str] | None = None

    def match(self, text: str) -> re.Match[str] | None:
        if self._compiled is None:
            self._compiled = re.compile(self._source)
        return self._compiled.match(text)


SEAL_RECORD = LazyPattern(
    rf"{re.escape(SEALS_DIR)}/(\d+)/{re.escape(SEAL_FILE)}$"
)
PROOF_FILE = LazyPattern(
    rf"{re.escape(SEALS_DIR)}/(\d+)/{re.escape(PROOF_DIR)}/([^/]+)/(.+)$"
)


class Kind(StrEnum):
    ADDED = "added"
    APPENDED = "appended"
    CHANGED = "changed"
    DELETED = "deleted"


# A file that exists before and after, with different bytes.
REWRITES = frozenset({Kind.APPENDED, Kind.CHANGED})


@dataclass(frozen=True)
class Change:
    """One changed path: a manifest key, relative to the data root."""

    kind: Kind
    path: str


def check_home(home: PurePosixPath) -> PurePosixPath:
    """The vault's home directory relative to the data root, in the same
    normalised form as a manifest key, so that paths compare by component
    and never by string prefix."""
    check_relpath(str(home))
    return home


@dataclass(frozen=True)
class ProofPath:
    """Where inside the seals a proof file lies."""

    seal: int
    authority: str
    name: str


def _inside(change: Change, home: PurePosixPath) -> str | None:
    """The path relative to the vault's home, or None outside it."""
    path = PurePosixPath(change.path)
    if path == home or not path.is_relative_to(home):
        return None
    return str(path.relative_to(home))


def _proof(change: Change, home: PurePosixPath) -> ProofPath | None:
    inside = _inside(change, home)
    if inside is None:
        return None
    found = PROOF_FILE.match(inside)
    if found is None:
        return None
    return ProofPath(int(found.group(1)), found.group(2), found.group(3))


def _seal_id(change: Change, home: PurePosixPath) -> int | None:
    """Id of the seal whose record a change touches."""
    inside = _inside(change, home)
    if inside is None:
        return None
    found = SEAL_RECORD.match(inside)
    return None if found is None else int(found.group(1))


@dataclass(frozen=True)
class ProofAbandoned:
    seal: int
    authority: str

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        if change.kind is not Kind.ADDED:
            return None
        proof = _proof(change, home)
        if proof is None or proof.name != ABANDONED_FILE:
            return None
        return cls(proof.seal, proof.authority)


@dataclass(frozen=True)
class ProofCompleted:
    seal: int
    authority: str

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        if change.kind is not Kind.ADDED:
            return None
        proof = _proof(change, home)
        if proof is None or proof.name == ABANDONED_FILE:
            return None
        return cls(proof.seal, proof.authority)


@dataclass(frozen=True)
class ProofTampered:
    """A proof file was rewritten or removed; nothing in a proof directory
    is ever rewritten, so this is never legitimate."""

    seal: int
    authority: str
    path: str

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        if change.kind is Kind.ADDED:
            return None
        proof = _proof(change, home)
        if proof is None:
            return None
        return cls(proof.seal, proof.authority, change.path)


@dataclass(frozen=True)
class SealAdded:
    seal: int

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        if change.kind is not Kind.ADDED:
            return None
        seal = _seal_id(change, home)
        return None if seal is None else cls(seal)


@dataclass(frozen=True)
class SealRemoved:
    seal: int

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        if change.kind is not Kind.DELETED:
            return None
        seal = _seal_id(change, home)
        return None if seal is None else cls(seal)


@dataclass(frozen=True)
class SealTampered:
    seal: int

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        if change.kind not in REWRITES:
            return None
        seal = _seal_id(change, home)
        return None if seal is None else cls(seal)


@dataclass(frozen=True)
class FileAdded:
    path: str

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        return cls(change.path) if change.kind is Kind.ADDED else None


@dataclass(frozen=True)
class FileAppended:
    path: str

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        return cls(change.path) if change.kind is Kind.APPENDED else None


@dataclass(frozen=True)
class FileChanged:
    path: str

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        return cls(change.path) if change.kind is Kind.CHANGED else None


@dataclass(frozen=True)
class FileDeleted:
    path: str

    @classmethod
    def make(cls, change: Change, home: PurePosixPath) -> Self | None:
        return cls(change.path) if change.kind is Kind.DELETED else None


type Event = (
    ProofAbandoned
    | ProofCompleted
    | ProofTampered
    | SealAdded
    | SealRemoved
    | SealTampered
    | FileAdded
    | FileAppended
    | FileChanged
    | FileDeleted
)

KINDS: tuple[type[Event], ...] = (
    ProofAbandoned,
    ProofCompleted,
    ProofTampered,
    SealAdded,
    SealRemoved,
    SealTampered,
    FileAdded,
    FileAppended,
    FileChanged,
    FileDeleted,
)


def flatten(changes: Changes) -> list[Change]:
    """Every changed path as a Change: added first, deleted last, sorted by
    path within each kind."""
    result: list[Change] = []
    for kind, paths in (
        (Kind.ADDED, changes.added),
        (Kind.APPENDED, changes.appended),
        (Kind.CHANGED, changes.changed),
        (Kind.DELETED, changes.deleted),
    ):
        result.extend(Change(kind, path) for path in sorted(paths))
    return result


def classify(changes: Changes, home: PurePosixPath) -> list[Event]:
    """One event per changed path, the most specific that applies, with
    repeats dropped: completing one proof adds several files but is one
    event. `home` is the vault's home directory relative to the data
    root."""
    check_home(home)
    events: dict[Event, None] = {}
    for change in flatten(changes):
        for kind in KINDS:
            event = kind.make(change, home)
            if event is not None:
                events[event] = None
                break
    return list(events)
