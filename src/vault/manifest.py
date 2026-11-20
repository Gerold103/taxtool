"""Manifests: which files a sealed directory holds and what they hash to.

A manifest is a sorted map from a relative POSIX path to its Digest. Its
YAML form is deterministic (sorted keys, block style, no aliases) so that
the same tree always produces the same bytes and therefore the same hash;
the hash of a manifest is what seals chain on.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

import yaml

from vault.errors import VaultError
from vault.hashing import Digest, is_sha256_hex

VERSION = 1


def check_relpath(path: str) -> str:
    """A manifest key: relative, normalised, POSIX, not escaping upwards."""
    pure = PurePosixPath(path)
    if (
        not path
        or pure.is_absolute()
        or str(pure) != path
        or ".." in pure.parts
        or "." in pure.parts
    ):
        raise VaultError(f"not a clean relative path: {path!r}")
    return path


@dataclass(frozen=True)
class Manifest:
    """Relative path -> Digest for every file under one directory."""

    files: Mapping[str, Digest] = field(default_factory=dict)

    def __post_init__(self) -> None:
        ordered = {check_relpath(p): self.files[p] for p in sorted(self.files)}
        object.__setattr__(self, "files", ordered)

    def to_yaml(self) -> str:
        data = {
            "version": VERSION,
            "files": {
                path: {"sha256": d.sha256, "size": d.size}
                for path, d in self.files.items()
            },
        }
        text: str = yaml.safe_dump(
            data, sort_keys=True, default_flow_style=False, width=80
        )
        return text

    @classmethod
    def from_yaml(cls, text: str) -> "Manifest":
        data = yaml.safe_load(text)
        if not isinstance(data, dict) or data.get("version") != VERSION:
            raise VaultError("not a manifest: missing or unknown version")
        files = data.get("files")
        if files is None:
            files = {}
        if not isinstance(files, dict):
            raise VaultError("not a manifest: files is not a mapping")
        return cls({str(p): _digest_from(p, e) for p, e in files.items()})


def _digest_from(path: Any, entry: Any) -> Digest:
    if (
        not isinstance(entry, dict)
        or not isinstance(entry.get("sha256"), str)
        or not is_sha256_hex(entry["sha256"])
        or not isinstance(entry.get("size"), int)
        or entry["size"] < 0
    ):
        raise VaultError(f"manifest entry for {path!r} is malformed")
    return Digest(entry["sha256"], entry["size"])


@dataclass(frozen=True)
class Changes:
    """Difference between two manifests, by path."""

    added: Mapping[str, Digest]
    changed: Mapping[str, tuple[Digest, Digest]]
    deleted: Mapping[str, Digest]

    def __bool__(self) -> bool:
        return bool(self.added or self.changed or self.deleted)

    def paths(self) -> Iterable[str]:
        return sorted({*self.added, *self.changed, *self.deleted})


def diff(old: Manifest, new: Manifest) -> Changes:
    """What `new` has that `old` had not, and the other way round."""
    added = {p: d for p, d in new.files.items() if p not in old.files}
    deleted = {p: d for p, d in old.files.items() if p not in new.files}
    changed = {
        p: (old.files[p], d)
        for p, d in new.files.items()
        if p in old.files and old.files[p] != d
    }
    return Changes(added, changed, deleted)
