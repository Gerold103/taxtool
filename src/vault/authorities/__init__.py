"""Timestamp authorities: who vouches that a root hash existed at a time.

An authority sees only the 64-hex root hash and the time of sealing. It
writes its proof into a directory of the seal, and later checks such a
proof offline against material saved locally: a certificate chain, a key,
a block header. Nothing here contacts the network except `stamp`.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from vault.errors import VaultError
from vault.hashing import is_sha256_hex


class Authority(Protocol):
    name: str

    async def stamp(self, root: str, now: datetime, proof_dir: Path) -> None:
        """Obtain a proof that `root` existed at `now`; write it under
        `proof_dir`, which exists and is empty."""

    async def verify(self, root: str, proof_dir: Path) -> datetime:
        """Check the proof in `proof_dir` for `root`, offline. Return the
        time it attests, or raise VaultError saying what is wrong."""


def check_root(root: str) -> str:
    if not is_sha256_hex(root):
        raise VaultError(f"root hash is not a sha256 hex digest: {root!r}")
    return root


def check_time(now: datetime) -> datetime:
    """Seal times are timezone-aware and recorded in UTC."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise VaultError("seal time must be timezone-aware")
    return now.astimezone(UTC)
