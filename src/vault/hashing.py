"""SHA-256 digests of bytes, files and file prefixes.

A digest here is always the lowercase hex SHA-256 together with the number
of bytes it covers, because manifests and seal markers need both and a
prefix proof is only meaningful with its length.
"""

import asyncio
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from vault.errors import VaultError

CHUNK_SIZE = 1024 * 1024
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Digest:
    """SHA-256 of some bytes, with how many bytes were hashed."""

    sha256: str
    size: int


def is_sha256_hex(value: str) -> bool:
    return _HEX_DIGEST.match(value) is not None


def digest_bytes(data: bytes) -> Digest:
    return Digest(hashlib.sha256(data).hexdigest(), len(data))


def _digest_stream(path: Path, limit: int | None) -> Digest:
    hasher = hashlib.sha256()
    remaining = limit
    size = 0
    with path.open("rb") as stream:
        while remaining is None or remaining > 0:
            want = (
                CHUNK_SIZE if remaining is None else min(CHUNK_SIZE, remaining)
            )
            chunk = stream.read(want)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    if limit is not None and size < limit:
        raise VaultError(
            f"{path}: expected at least {limit} bytes for a prefix digest, "
            f"the file has {size}"
        )
    return Digest(hasher.hexdigest(), size)


async def digest_file(path: Path) -> Digest:
    """Hash a whole file without holding it in memory."""
    return await asyncio.to_thread(_digest_stream, path, None)


async def digest_prefix(path: Path, length: int) -> Digest:
    """Hash the first `length` bytes of a file, as seal markers record."""
    if length < 0:
        raise VaultError(f"{path}: prefix length must not be negative")
    return await asyncio.to_thread(_digest_stream, path, length)


def blob_relpath(sha256: str) -> Path:
    """Where a blob with this digest lives inside an object store."""
    if not is_sha256_hex(sha256):
        raise VaultError(f"not a sha256 hex digest: {sha256!r}")
    return Path(sha256[:2]) / sha256[2:]
