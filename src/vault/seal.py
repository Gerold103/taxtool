"""Seals: a signed statement of everything under the data root at a time.

A seal is a directory `seals/NNNNNN/` in the vault's home directory. Its
record `seal.yaml` names the root tree object of the data root as scanned,
the time, the previous seal's root hash and the authorities asked. The
SHA-256 of the record's bytes is the root hash the authorities stamp, so
one proof covers the tree, the time and the chain link at once.

Each authority writes its proof under `proof/<name>/`. A proof that an
authority will never finish is abandoned by writing `abandoned.yaml` next
to it; nothing in a seal directory is ever rewritten, because the next
seal covers it like any other file. Creating a seal requires at least
one authority to accept the root hash, complete or pending; the vault
reports what each authority said and the caller decides what to tell the
user.

Vocabulary: a SealRecord is the content of `seal.yaml`; a Seal is that
record as found on disk, with its hash and directory; a ProofStatus is
what one authority's proof is right now; a SealStatus is one Seal with
the ProofStatus of each authority it asked.
"""

import asyncio
import os
import shutil
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from vault import tree
from vault.authorities import Authority, Complete, Pending, check_time
from vault.errors import VaultError
from vault.events import (
    ABANDONED_FILE,
    PROOF_DIR,
    SEAL_FILE,
    SEALS_DIR,
    check_home,
)
from vault.hashing import Digest, digest_bytes, is_sha256_hex
from vault.manifest import parse_digest
from vault.objects import READ_ONLY, ObjectStore
from vault.scan import scan
from vault.tree import check_name

VERSION = 1
OBJECTS_DIR = "objects"
CACHE_FILE = "cache"
# Seal directories sort by name, so ids are zero-padded. Six digits is
# one seal a day for 2700 years.
ID_WIDTH = 6


def _parse_time(value: Any, what: str) -> datetime:
    """A UTC time from YAML, written as a string or parsed as a timestamp
    by YAML itself when the string was not quoted."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            raise VaultError(f"{what}: unreadable time {value!r}") from None
    if not isinstance(value, datetime):
        raise VaultError(f"{what}: time is missing")
    return check_time(value)


@dataclass(frozen=True)
class SealRecord:
    """The content of `seal.yaml`: what was sealed, when, after which seal
    and by whom. Its bytes are what the authorities sign."""

    id: int
    time: datetime
    tree: Digest
    previous: str | None
    authorities: tuple[str, ...]

    def to_yaml(self) -> str:
        data = {
            "version": VERSION,
            "id": self.id,
            "time": self.time.isoformat(),
            "tree": {"sha256": self.tree.sha256, "size": self.tree.size},
            "previous": self.previous,
            "authorities": list(self.authorities),
        }
        text: str = yaml.safe_dump(
            data, sort_keys=False, default_flow_style=False, width=80
        )
        return text

    @classmethod
    def from_yaml(cls, text: str) -> "SealRecord":
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise VaultError("not a seal record: not YAML") from error
        if not isinstance(data, dict) or data.get("version") != VERSION:
            raise VaultError("not a seal record: missing or unknown version")
        seal_id = data.get("id")
        if not isinstance(seal_id, int) or seal_id < 1:
            raise VaultError("seal record: id is not a positive integer")
        what = f"seal {seal_id}"
        time = _parse_time(data.get("time"), what)
        root = parse_digest("tree", data.get("tree"))
        previous = data.get("previous")
        if previous is not None and (
            not isinstance(previous, str) or not is_sha256_hex(previous)
        ):
            raise VaultError(f"{what}: previous is not a sha256 hex digest")
        names = data.get("authorities")
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(n, str) for n in names)
        ):
            raise VaultError(f"{what}: authorities must be a list of names")
        return cls(seal_id, time, root, previous, tuple(names))


@dataclass(frozen=True)
class Seal:
    """A seal as found on disk: its record, the hash of the record's bytes
    that the authorities stamped, and its directory `seals/NNNNNN/`, which
    holds the record and a `proof/<authority>/` directory per proof."""

    record: SealRecord
    root: str
    dir: Path

    @property
    def id(self) -> int:
        return self.record.id


@dataclass(frozen=True)
class Abandoned:
    """The owner gave the proof up at `time`; it is not asked again."""

    time: datetime
    why: str


@dataclass(frozen=True)
class Failed:
    """The authority raised: the proof is absent or does not hold."""

    why: str


type ProofStatus = Complete | Pending | Abandoned | Failed


@dataclass(frozen=True)
class SealStatus:
    """One seal with what each authority it asked says about its proof."""

    seal: Seal
    proofs: Mapping[str, ProofStatus]


def seal_dir(home: Path, seal_id: int) -> Path:
    return home / SEALS_DIR / f"{seal_id:0{ID_WIDTH}d}"


def proof_dir(seal: Seal, authority: str) -> Path:
    return seal.dir / PROOF_DIR / authority


def ids(home: Path) -> list[int]:
    """Ids of the seal directories present, ascending."""
    seals = home / SEALS_DIR
    if not seals.is_dir():
        return []
    return sorted(
        int(entry.name)
        for entry in seals.iterdir()
        if entry.is_dir()
        and entry.name.isdigit()
        and len(entry.name) == ID_WIDTH
    )


def _load(home: Path, seal_id: int) -> Seal:
    path = seal_dir(home, seal_id) / SEAL_FILE
    if not path.is_file():
        raise VaultError(f"seal {seal_id}: no record at {path}")
    data = path.read_bytes()
    try:
        record = SealRecord.from_yaml(data.decode())
    except UnicodeDecodeError as error:
        raise VaultError(f"seal {seal_id}: {path} is not UTF-8") from error
    if record.id != seal_id:
        raise VaultError(f"seal {seal_id}: {path} says it is seal {record.id}")
    return Seal(record, digest_bytes(data).sha256, path.parent)


async def load(home: Path, seal_id: int) -> Seal:
    return await asyncio.to_thread(_load, home, seal_id)


async def latest(home: Path) -> Seal | None:
    present = ids(home)
    return await load(home, present[-1]) if present else None


def _inside(root: Path, home: Path) -> PurePosixPath:
    """The home directory relative to the data root, as a manifest key."""
    try:
        relative = home.resolve().relative_to(root.resolve())
    except ValueError:
        raise VaultError(
            f"vault home {home} is not inside the data root {root}"
        ) from None
    return check_home(PurePosixPath(relative.as_posix()))


def _by_name(authorities: Sequence[Authority]) -> dict[str, Authority]:
    by_name: dict[str, Authority] = {}
    for authority in authorities:
        check_name(authority.name)
        if authority.name in by_name:
            raise VaultError(f"two authorities are named {authority.name!r}")
        by_name[authority.name] = authority
    return by_name


def _write_record(home: Path, record: SealRecord) -> Seal:
    directory = seal_dir(home, record.id)
    try:
        directory.mkdir(parents=True)
    except FileExistsError:
        raise VaultError(
            f"seal {record.id}: {directory} already exists"
        ) from None
    data = record.to_yaml().encode()
    path = directory / SEAL_FILE
    path.write_bytes(data)
    os.chmod(path, READ_ONLY)
    return Seal(record, digest_bytes(data).sha256, directory)


async def create(
    root: Path,
    home: Path,
    authorities: Sequence[Authority],
    now: datetime,
    exclude: Collection[str] = (),
) -> SealStatus:
    """Scan the data root, store its tree, write the next seal record and
    ask every authority to stamp it.

    `exclude` lists paths relative to `root` to leave out of the tree; the
    object store and the stat cache are always left out, because the store
    is reached by hash and the cache is derived data. The seal is kept if
    at least one authority accepts the root hash, and removed again with
    an error naming every failure if none does.
    """
    if not authorities:
        raise VaultError("sealing needs at least one authority")
    by_name = _by_name(authorities)
    inside = _inside(root, home)
    now = check_time(now)
    store = ObjectStore(home / OBJECTS_DIR)
    manifest = await scan(
        root,
        [*exclude, str(inside / OBJECTS_DIR), str(inside / CACHE_FILE)],
        home / CACHE_FILE,
    )
    top = await tree.write(store, manifest)
    before = await latest(home)
    seal_id = 1 if before is None else before.id + 1
    previous = None if before is None else before.root
    record = SealRecord(seal_id, now, top, previous, tuple(by_name))
    seal = await asyncio.to_thread(_write_record, home, record)
    proofs: dict[str, ProofStatus] = {}
    for name, authority in by_name.items():
        directory = proof_dir(seal, name)
        directory.mkdir(parents=True)
        try:
            proofs[name] = await authority.stamp(seal.root, now, directory)
        except VaultError as error:
            proofs[name] = Failed(str(error))
    failures = [
        f"{n}: {p.why}" for n, p in proofs.items() if isinstance(p, Failed)
    ]
    if len(failures) == len(proofs):
        await asyncio.to_thread(shutil.rmtree, seal.dir)
        raise VaultError(
            f"seal {seal_id}: no authority accepted it: {'; '.join(failures)}"
        )
    return SealStatus(seal, proofs)


def _read_abandoned(directory: Path) -> Abandoned | None:
    path = directory / ABANDONED_FILE
    if not path.is_file():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("why"), str):
        raise VaultError(f"{path} is malformed")
    return Abandoned(_parse_time(data.get("time"), str(path)), data["why"])


def _write_abandoned(directory: Path, marker: Abandoned) -> None:
    if not directory.is_dir():
        raise VaultError(f"no proof directory {directory}")
    path = directory / ABANDONED_FILE
    if path.exists():
        raise VaultError(f"{path} already exists")
    data = {"time": marker.time.isoformat(), "why": marker.why}
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    os.chmod(path, READ_ONLY)


async def abandon(
    home: Path, seal_id: int, authority: str, now: datetime, why: str
) -> Abandoned:
    """Give up the proof of `authority` for seal `seal_id` by writing the
    marker file; `complete` skips it from then on."""
    if not why.strip():
        raise VaultError("abandoning a proof needs a reason")
    seal = await load(home, seal_id)
    if authority not in seal.record.authorities:
        raise VaultError(f"seal {seal_id} did not ask authority {authority!r}")
    marker = Abandoned(check_time(now), why)
    await asyncio.to_thread(
        _write_abandoned, proof_dir(seal, authority), marker
    )
    return marker


async def _complete_one(
    seal: Seal, by_name: Mapping[str, Authority]
) -> SealStatus:
    proofs: dict[str, ProofStatus] = {}
    for name in seal.record.authorities:
        directory = proof_dir(seal, name)
        marker = await asyncio.to_thread(_read_abandoned, directory)
        if marker is not None:
            proofs[name] = marker
            continue
        authority = by_name.get(name)
        if authority is None:
            proofs[name] = Failed(f"authority {name!r} is not configured")
            continue
        try:
            proofs[name] = await authority.complete(seal.root, directory)
        except VaultError as error:
            proofs[name] = Failed(str(error))
    return SealStatus(seal, proofs)


async def complete(
    home: Path, authorities: Sequence[Authority], seal_id: int | None = None
) -> list[SealStatus]:
    """Ask every authority of one seal, or of every seal, to finish its
    proof; abandoned proofs are reported as such and not asked."""
    by_name = _by_name(authorities)
    chosen = ids(home) if seal_id is None else [seal_id]
    statuses = []
    for chosen_id in chosen:
        seal = await load(home, chosen_id)
        statuses.append(await _complete_one(seal, by_name))
    return statuses
