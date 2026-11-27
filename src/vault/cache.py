"""Digests remembered between scans, keyed by what identifies a file
cheaply.

Hashing every file on every scan reads all the data; a stat does not.
Like git's index, the cache keeps for each path the size, the modification
time in nanoseconds and the digest seen last, and a digest is reused only
while size and mtime still match. A file modified at or after the moment
the previous scan started is hashed again regardless: its mtime could
equal the recorded one while its content differs (git calls such an entry
racy).

The cache is derived data. Deleting it costs one full scan and changes
nothing else, and a scan without a cache ignores it. A file edited and
then given back its old size and mtime defeats it, as it defeats git.

The file is plain text: a header line, then one line per path with the
digest, size, mtime and path, the path last because it may contain
spaces.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from vault.errors import VaultError
from vault.hashing import Digest, is_sha256_hex
from vault.manifest import check_relpath

CACHE_HEADER = "vault-stat-cache"
VERSION = 1


@dataclass(frozen=True)
class CacheEntry:
    """What was known about one file when it was last hashed."""

    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class StatCache:
    """Entries of the previous scan and the time that scan started."""

    started_ns: int = 0
    entries: Mapping[str, CacheEntry] = field(default_factory=dict)

    def lookup(self, rel: str, st: os.stat_result) -> Digest | None:
        """The remembered digest if `st` still identifies the same file."""
        entry = self.entries.get(rel)
        if (
            entry is None
            or entry.size != st.st_size
            or entry.mtime_ns != st.st_mtime_ns
            or st.st_mtime_ns >= self.started_ns
        ):
            return None
        return Digest(entry.sha256, entry.size)


def _parse_entry(line: str) -> tuple[str, CacheEntry]:
    sha256, size, mtime_ns, rel = line.split(" ", 3)
    if not is_sha256_hex(sha256):
        raise ValueError(sha256)
    return check_relpath(rel), CacheEntry(int(size), int(mtime_ns), sha256)


def load_stat_cache(path: Path) -> StatCache:
    """Blocking read; a missing file is an empty cache, a malformed one
    is an error, since the fix (delete it) must be the user's choice."""
    if not path.is_file():
        return StatCache()
    try:
        header, *lines = path.read_text(encoding="utf-8").splitlines()
        name, version, started_ns = header.split(" ")
        if name != CACHE_HEADER or int(version) != VERSION:
            raise ValueError(header)
        entries = dict(_parse_entry(line) for line in lines)
        return StatCache(int(started_ns), entries)
    except (ValueError, VaultError) as exc:
        raise VaultError(
            f"{path}: stat cache is unreadable ({exc}); delete it to rebuild"
        ) from exc


def save_stat_cache(path: Path, cache: StatCache) -> None:
    """Blocking atomic write."""
    lines = [f"{CACHE_HEADER} {VERSION} {cache.started_ns}"]
    for rel in sorted(cache.entries):
        e = cache.entries[rel]
        lines.append(f"{e.sha256} {e.size} {e.mtime_ns} {rel}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(temp, path)
