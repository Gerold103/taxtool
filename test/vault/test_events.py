import re
from pathlib import PurePosixPath
from typing import get_args

import pytest

from vault.errors import VaultError
from vault.events import (
    EVENT_KINDS,
    Change,
    ChangeKind,
    Event,
    FileAdded,
    FileAppended,
    FileChanged,
    FileDeleted,
    LazyPattern,
    ProofAbandoned,
    ProofCompleted,
    ProofTampered,
    SealAdded,
    SealRemoved,
    SealTampered,
    check_home,
    classify_changes,
    flatten_changes,
)
from vault.hashing import digest_bytes
from vault.scan import Changes

HOME = PurePosixPath(".app/.vault")
SEAL = ".app/.vault/seals/000003/seal.yaml"
PROOF = ".app/.vault/seals/000003/proof/ots/root.ots"
MARKER = ".app/.vault/seals/000003/proof/ots/abandoned.yaml"
A = digest_bytes(b"a")
B = digest_bytes(b"b")

GENERIC: dict[ChangeKind, type[Event]] = {
    ChangeKind.ADDED: FileAdded,
    ChangeKind.APPENDED: FileAppended,
    ChangeKind.CHANGED: FileChanged,
    ChangeKind.DELETED: FileDeleted,
}


def one(kind: ChangeKind, path: str) -> Changes:
    match kind:
        case ChangeKind.ADDED:
            return Changes({path: A}, {}, {}, {})
        case ChangeKind.APPENDED:
            return Changes({}, {path: (A, B)}, {}, {})
        case ChangeKind.CHANGED:
            return Changes({}, {}, {path: (A, B)}, {})
        case ChangeKind.DELETED:
            return Changes({}, {}, {}, {path: A})


def test_kinds_lists_every_event_once() -> None:
    assert len(EVENT_KINDS) == len(set(EVENT_KINDS))
    assert set(EVENT_KINDS) == set(get_args(Event.__value__))


@pytest.mark.parametrize(
    ("kind", "path", "expected"),
    [
        (ChangeKind.ADDED, SEAL, SealAdded(3)),
        (ChangeKind.APPENDED, SEAL, SealTampered(3)),
        (ChangeKind.CHANGED, SEAL, SealTampered(3)),
        (ChangeKind.DELETED, SEAL, SealRemoved(3)),
        (ChangeKind.ADDED, PROOF, ProofCompleted(3, "ots")),
        (ChangeKind.APPENDED, PROOF, ProofTampered(3, "ots", PROOF)),
        (ChangeKind.CHANGED, PROOF, ProofTampered(3, "ots", PROOF)),
        (ChangeKind.DELETED, PROOF, ProofTampered(3, "ots", PROOF)),
        (ChangeKind.ADDED, MARKER, ProofAbandoned(3, "ots")),
        (ChangeKind.CHANGED, MARKER, ProofTampered(3, "ots", MARKER)),
        (ChangeKind.DELETED, MARKER, ProofTampered(3, "ots", MARKER)),
        (ChangeKind.ADDED, "docs/x.pdf", FileAdded("docs/x.pdf")),
        (ChangeKind.APPENDED, "log/l.yaml", FileAppended("log/l.yaml")),
        (ChangeKind.CHANGED, "config.yaml", FileChanged("config.yaml")),
        (ChangeKind.DELETED, "docs/x.pdf", FileDeleted("docs/x.pdf")),
    ],
)
def test_one_change_gives_its_event(
    kind: ChangeKind, path: str, expected: Event
) -> None:
    assert classify_changes(one(kind, path), HOME) == [expected]


@pytest.mark.parametrize("path", [SEAL, PROOF, MARKER])
@pytest.mark.parametrize("kind", list(ChangeKind))
def test_every_make_decides_on_its_own(kind: ChangeKind, path: str) -> None:
    """The order of EVENT_KINDS picks among fitting events; it never has to
    shield a class from a change it does not fit."""
    change = Change(kind, path)
    accepting = [k for k in EVENT_KINDS if k.make(change, HOME) is not None]
    [specific] = classify_changes(one(kind, path), HOME)
    assert accepting == [type(specific), GENERIC[kind]]


@pytest.mark.parametrize(
    "path",
    [
        ".app/.vault/authorities.yaml",
        ".app/.vault/authorities/tsa/chain.pem",
        ".app/.vault/seals/000003/notes.txt",
        ".app/.vault/seals/latest/seal.yaml",
        ".app/.vault/seals/000003/proof/seal.yaml",
    ],
)
def test_other_vault_files_are_generic(path: str) -> None:
    assert classify_changes(one(ChangeKind.ADDED, path), HOME) == [
        FileAdded(path)
    ]


def test_home_is_compared_by_component_not_prefix() -> None:
    path = ".app/.vaultx/seals/000003/seal.yaml"
    assert classify_changes(one(ChangeKind.ADDED, path), HOME) == [
        FileAdded(path)
    ]
    assert classify_changes(
        one(ChangeKind.ADDED, SEAL), PurePosixPath(".app")
    ) == [FileAdded(SEAL)]
    assert classify_changes(one(ChangeKind.ADDED, str(HOME)), HOME) == [
        FileAdded(str(HOME))
    ]


def test_seal_id_is_parsed() -> None:
    path = ".app/.vault/seals/000012/seal.yaml"
    assert classify_changes(one(ChangeKind.ADDED, path), HOME) == [
        SealAdded(12)
    ]


def test_completing_one_proof_is_one_event() -> None:
    changes = Changes(
        {
            ".app/.vault/seals/000003/proof/ots/root.ots": A,
            ".app/.vault/seals/000003/proof/ots/block-header.bin": B,
            ".app/.vault/seals/000003/proof/tsa/token.tsr": A,
        },
        {},
        {},
        {},
    )
    assert classify_changes(changes, HOME) == [
        ProofCompleted(3, "ots"),
        ProofCompleted(3, "tsa"),
    ]


def test_flatten_orders_by_kind_then_path() -> None:
    changes = Changes(
        {"b": A, "a": A}, {"log": (A, B)}, {"c": (A, B)}, {"z": A}
    )
    assert flatten_changes(changes) == [
        Change(ChangeKind.ADDED, "a"),
        Change(ChangeKind.ADDED, "b"),
        Change(ChangeKind.APPENDED, "log"),
        Change(ChangeKind.CHANGED, "c"),
        Change(ChangeKind.DELETED, "z"),
    ]


def test_no_changes_give_no_events() -> None:
    assert classify_changes(Changes({}, {}, {}, {}), HOME) == []


@pytest.mark.parametrize("home", ["", "/abs", "a/../b", "."])
def test_unclean_home_is_rejected(home: str) -> None:
    with pytest.raises(VaultError):
        check_home(PurePosixPath(home))
    with pytest.raises(VaultError):
        classify_changes(one(ChangeKind.ADDED, "x"), PurePosixPath(home))


def test_lazy_pattern_compiles_on_first_match() -> None:
    assert LazyPattern(r"a(b)$").match("ab") is not None
    assert LazyPattern(r"a(b)$").match("abc") is None
    broken = LazyPattern("(")
    with pytest.raises(re.error):
        broken.match("x")
