"""Working-tree scanning: from a directory on disk to a Manifest, and from
an old and a new Manifest to the changes a seal records.

An "appended" change is a fact about bytes, not a policy: the old content
is a prefix of the new. The vault reports it for every grown file; whether
an append is legitimate at a given path is for the caller to decide.
"""

import asyncio
import os
import stat
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path

from vault.cache import Entry, StatCache, load, save
from vault.errors import VaultError
from vault.hashing import Digest, digest_prefix, digest_stream
from vault.manifest import Manifest, check_relpath


def _excluded(rel: str, exclude: Collection[str]) -> bool:
    return any(rel == e or rel.startswith(e + "/") for e in exclude)


def _collect(
    root: Path, exclude: Collection[str]
) -> list[tuple[str, Path, os.stat_result]]:
    found: list[tuple[str, Path, os.stat_result]] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if _excluded(rel, exclude):
            continue
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise VaultError(f"{path}: symlinks are not allowed in the tree")
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise VaultError(f"{path}: not a regular file")
        found.append((rel, path, st))
    return found


def _scan(root: Path, exclude: Collection[str], cache: Path | None) -> Manifest:
    if not root.is_dir():
        raise VaultError(f"{root}: not a directory")
    for entry in exclude:
        check_relpath(entry)
    started_ns = time.time_ns()
    known = load(cache) if cache else StatCache()
    files: dict[str, Digest] = {}
    entries: dict[str, Entry] = {}
    for rel, path, st in _collect(root, exclude):
        digest = known.lookup(rel, st) or digest_stream(path, None)
        files[rel] = digest
        entries[rel] = Entry(st.st_size, st.st_mtime_ns, digest.sha256)
    if cache:
        save(cache, StatCache(started_ns, entries))
    return Manifest(files)


async def scan(
    root: Path, exclude: Collection[str] = (), cache: Path | None = None
) -> Manifest:
    """Hash every regular file under root, except excluded paths.

    `exclude` lists relative POSIX paths of files or directories to leave
    out; a directory is skipped with everything below it. Symlinks and
    special files are errors, because a sealed tree must be plain files
    whose bytes are what the hash covers. With `cache`, digests of files
    whose size and mtime are unchanged since the previous scan are reused
    and the file is rewritten for the next one; see vault.cache.
    """
    return await asyncio.to_thread(_scan, root, exclude, cache)


@dataclass(frozen=True)
class Changes:
    """Difference between two manifests of the same directory, by path.

    `appended` holds grown files whose old content is still their prefix;
    `changed` holds every other file whose digest differs.
    """

    added: Mapping[str, Digest]
    appended: Mapping[str, tuple[Digest, Digest]]
    changed: Mapping[str, tuple[Digest, Digest]]
    deleted: Mapping[str, Digest]

    def __bool__(self) -> bool:
        return bool(self.added or self.appended or self.changed or self.deleted)

    def paths(self) -> list[str]:
        return sorted(
            {*self.added, *self.appended, *self.changed, *self.deleted}
        )


async def changes(root: Path, old: Manifest, new: Manifest) -> Changes:
    """Compare two manifests of `root`; `new` must describe its current
    files, since appends are confirmed by hashing the file's prefix."""
    added = {p: d for p, d in new.files.items() if p not in old.files}
    deleted = {p: d for p, d in old.files.items() if p not in new.files}
    appended: dict[str, tuple[Digest, Digest]] = {}
    changed: dict[str, tuple[Digest, Digest]] = {}
    for rel, new_digest in new.files.items():
        old_digest = old.files.get(rel)
        if old_digest is None or old_digest == new_digest:
            continue
        if new_digest.size > old_digest.size:
            prefix = await digest_prefix(root / rel, old_digest.size)
            if prefix == old_digest:
                appended[rel] = (old_digest, new_digest)
                continue
        changed[rel] = (old_digest, new_digest)
    return Changes(added, appended, changed, deleted)
