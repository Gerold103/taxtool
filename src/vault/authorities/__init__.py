"""Timestamp authorities: who vouches that a root hash existed at a time.

An authority sees only the 64-hex root hash and the time of sealing. It
writes its proof into a directory of the seal, and later checks such a
proof offline against material saved locally: a certificate chain, a key,
a block header. Only `stamp` and `complete` contact the network.

A proof that exists is Complete, attesting a time and verifying offline,
or Pending: the authority accepted the hash but its final attestation
does not exist yet, as with a calendar that waits for a Bitcoin block.
`complete` asks for it later and may add files to the proof directory,
but never rewrites one, since a later seal may already cover it. A proof
that is absent or does not hold is a VaultError saying why.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from vault.errors import VaultError
from vault.hashing import is_sha256_hex


@dataclass(frozen=True)
class Complete:
    """The proof verifies offline and attests this UTC time."""

    time: datetime


@dataclass(frozen=True)
class Pending:
    """Accepted at `since`; the final attestation is not available yet."""

    since: datetime
    why: str


class Authority(Protocol):
    name: str

    async def stamp(
        self, root: str, now: datetime, proof_dir: Path
    ) -> Complete | Pending:
        """Obtain a proof that `root` existed at `now`; write it under
        `proof_dir`, which exists and is empty."""

    async def complete(self, root: str, proof_dir: Path) -> Complete | Pending:
        """Try to finish a pending proof, adding files next to the existing
        ones. On a proof that is already complete, same as `verify`."""

    async def verify(self, root: str, proof_dir: Path) -> Complete | Pending:
        """Check the proof in `proof_dir` for `root`, offline. Raise
        VaultError saying what is wrong if it does not hold."""


def check_root_hash(root: str) -> str:
    if not is_sha256_hex(root):
        raise VaultError(f"root hash is not a sha256 hex digest: {root!r}")
    return root


def check_time(now: datetime) -> datetime:
    """Seal times are timezone-aware and recorded in UTC."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise VaultError("seal time must be timezone-aware")
    return now.astimezone(UTC)
