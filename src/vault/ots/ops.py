"""The operations of a proof: how one message becomes the next.

Five are defined: append and prepend some bytes, or hash with SHA-256,
SHA-1 or RIPEMD-160. A path from our digest to a block's merkle root is
a sequence of them. The one-byte tags are the reference implementation's
and consensus critical; the hash tags are the OpenPGP algorithm numbers
of RFC 4880.
"""

import hashlib
from dataclasses import dataclass

from vault.ots.wire import FormatError, Reader, varbytes

TAG_SHA1 = 0x02
TAG_RIPEMD160 = 0x03
TAG_SHA256 = 0x08
TAG_APPEND = 0xF0
TAG_PREPEND = 0xF1
HASH_BY_TAG = {
    TAG_SHA1: "sha1",
    TAG_RIPEMD160: "ripemd160",
    TAG_SHA256: "sha256",
}

# The reference refuses messages and results above this, so that a
# hostile proof cannot make a verifier allocate without bound.
MAX_LENGTH = 4096


@dataclass(frozen=True, order=True)
class Op:
    """One step of a path. `arg` is the bytes to add; empty for a hash."""

    tag: int
    arg: bytes = b""

    def apply(self, msg: bytes) -> bytes:
        if len(msg) > MAX_LENGTH:
            raise FormatError(f"message of {len(msg)} bytes is too long")
        if self.tag == TAG_APPEND:
            result = msg + self.arg
        elif self.tag == TAG_PREPEND:
            result = self.arg + msg
        else:
            result = hashlib.new(HASH_BY_TAG[self.tag], msg).digest()
        if len(result) > MAX_LENGTH:
            raise FormatError(f"result of {len(result)} bytes is too long")
        return result

    def serialize(self) -> bytes:
        if self.tag in HASH_BY_TAG:
            return bytes([self.tag])
        return bytes([self.tag]) + varbytes(self.arg)


def parse_op(reader: Reader, tag: int) -> Op:
    """The rest of an operation whose tag byte was already read."""
    if tag in HASH_BY_TAG:
        return Op(tag)
    if tag in (TAG_APPEND, TAG_PREPEND):
        return Op(tag, reader.varbytes(MAX_LENGTH, min_length=1))
    raise FormatError(f"unknown operation tag 0x{tag:02x}")
