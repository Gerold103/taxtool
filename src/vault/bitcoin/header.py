"""A Bitcoin block header: the 80 bytes that miners hash.

A block holds thousands of transactions. The header summarises them in
one merkle root and carries the time the miner claimed and the nonce
that makes the header's own hash fall under the difficulty target. The
rest of the block is never needed here.
"""

import hashlib
import struct
from dataclasses import dataclass
from datetime import UTC, datetime

from vault.errors import VaultError

# The header layout from the Bitcoin developer reference, as a struct
# format: little-endian ("<"), then version (L, 4-byte unsigned),
# previous block hash (32s, 32 bytes), merkle root (32s), time (L),
# difficulty bits (L), nonce (L).
FORMAT = "<L32s32sLLL"
SIZE = struct.calcsize(FORMAT)

# Difficulty bits are a compact float, Bitcoin Core's SetCompact: the
# high byte is a base-256 exponent, the low 23 bits the mantissa (bit 23
# is a sign bit that a valid header never sets).
BITS_EXPONENT_SHIFT = 24
BITS_MANTISSA_MASK = 0x007FFFFF
BITS_MANTISSA_BYTES = 3


@dataclass(frozen=True)
class BlockHeader:
    """The six header fields. `previous` and `merkle_root` are in the
    internal byte order, which is the order proofs use too."""

    version: int
    previous: bytes
    merkle_root: bytes
    seconds: int
    bits: int
    nonce: int

    @classmethod
    def parse(cls, raw: bytes) -> "BlockHeader":
        if len(raw) != SIZE:
            raise VaultError(f"block header has {len(raw)} bytes, not {SIZE}")
        return cls(*struct.unpack(FORMAT, raw))

    @property
    def raw(self) -> bytes:
        """The 80 bytes as mined and hashed."""
        return struct.pack(
            FORMAT,
            self.version,
            self.previous,
            self.merkle_root,
            self.seconds,
            self.bits,
            self.nonce,
        )

    @property
    def time(self) -> datetime:
        return datetime.fromtimestamp(self.seconds, UTC)

    @property
    def target(self) -> int:
        """The number the block hash must not exceed, from the bits."""
        exponent = self.bits >> BITS_EXPONENT_SHIFT
        mantissa = self.bits & BITS_MANTISSA_MASK
        return mantissa << (8 * (exponent - BITS_MANTISSA_BYTES))

    @property
    def hash(self) -> str:
        """The block hash as explorers display it: double SHA-256 of the
        header, printed as a big-endian number."""
        digest = hashlib.sha256(hashlib.sha256(self.raw).digest()).digest()
        return digest[::-1].hex()

    def check(self) -> None:
        """Proof of work; cheap, and enough to reject a header that was
        made up rather than mined."""
        if int(self.hash, 16) > self.target:
            raise VaultError("block header fails its own proof of work")
