"""Content-addressed object store: one read-only file per distinct blob.

Blobs live at `<root>/ab/cdef...` named by their SHA-256. Writing is
atomic (temporary file, then rename), so a crash never leaves a half
blob under a valid name, and stored files are made read-only so that an
accidental edit fails loudly instead of silently corrupting history.

The hash is the identity of the content, as it is for every manifest,
seal and auditor check above this layer. Storing content whose blob
already exists therefore re-reads that blob: if it no longer hashes to
its own name, that is CorruptObjectError; if it is intact but differs
from the new content, that is HashCollisionError and the existing blob
is kept. The store only reports; whether a collision stops the caller is
the caller's decision.
"""

import asyncio
import filecmp
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

from vault.errors import CorruptObjectError, HashCollisionError, VaultError
from vault.hashing import (
    Digest,
    blob_relpath,
    digest_bytes,
    digest_stream,
    is_sha256_hex,
)

READ_ONLY = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH


def check_blob(blob: Path, sha256: str) -> None:
    """Raise CorruptObjectError unless the blob hashes to its name."""
    actual = digest_stream(blob, None)
    if actual.sha256 != sha256:
        raise CorruptObjectError(sha256, actual.sha256)


def check_same_content(blob: Path, incoming: Path, sha256: str) -> None:
    """`incoming` hashes to `sha256`; it must equal the intact blob stored
    under that name. Raises CorruptObjectError or HashCollisionError."""
    check_blob(blob, sha256)
    if not filecmp.cmp(blob, incoming, shallow=False):
        raise HashCollisionError(sha256, str(incoming))


class ObjectStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, sha256: str) -> Path:
        return self.root / blob_relpath(sha256)

    def has(self, sha256: str) -> bool:
        return self.path(sha256).is_file()

    def _temp_file(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        handle, name = tempfile.mkstemp(prefix="incoming-", dir=self.root)
        os.close(handle)
        return Path(name)

    def _store(self, temp: Path, sha256: str) -> None:
        """Consume the temporary file: move it into place, or discard it
        after confirming the existing blob holds the same content."""
        blob = self.path(sha256)
        if blob.is_file():
            try:
                check_same_content(blob, temp, sha256)
            finally:
                temp.unlink()
            return
        blob.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(temp, READ_ONLY)
        os.replace(temp, blob)

    def _put_bytes(self, data: bytes) -> Digest:
        digest = digest_bytes(data)
        temp = self._temp_file()
        temp.write_bytes(data)
        self._store(temp, digest.sha256)
        return digest

    def _put_file(self, source: Path) -> Digest:
        digest = digest_stream(source, None)
        temp = self._temp_file()
        shutil.copyfile(source, temp)
        self._store(temp, digest.sha256)
        return digest

    async def put_bytes(self, data: bytes) -> Digest:
        return await asyncio.to_thread(self._put_bytes, data)

    async def put_file(self, source: Path) -> Digest:
        """Store a copy of a file; the original is left untouched."""
        return await asyncio.to_thread(self._put_file, source)

    async def get(self, sha256: str) -> bytes:
        path = self.path(sha256)
        if not path.is_file():
            raise VaultError(f"no object {sha256} in {self.root}")
        return await asyncio.to_thread(path.read_bytes)

    def _check(self, sha256: str) -> None:
        path = self.path(sha256)
        if not path.is_file():
            raise VaultError(f"no object {sha256} in {self.root}")
        check_blob(path, sha256)

    async def check(self, sha256: str) -> None:
        """Raise if the blob is missing or its content no longer matches."""
        await asyncio.to_thread(self._check, sha256)

    def __iter__(self) -> Iterator[str]:
        """Digests of all stored blobs, in no particular order."""
        if not self.root.is_dir():
            return
        for shard in self.root.iterdir():
            if not shard.is_dir() or len(shard.name) != 2:
                continue
            for blob in shard.iterdir():
                digest = shard.name + blob.name
                if blob.is_file() and is_sha256_hex(digest):
                    yield digest
