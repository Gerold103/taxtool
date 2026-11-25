"""The detached proof file, `.ots`.

A proof tree starts at a digest, and a detached file stores that digest
so the file stands on its own next to the data it is about. Layout: a
31-byte magic header that reads "OpenTimestamps Proof" in a hex dump, a
version byte, the one-byte tag of the hash the digest was made with,
the digest itself, then the root node. Only SHA-256 digests are written
or accepted here; the vault has no other.

The magic and version are the reference implementation's. Every proof
ever made starts with this magic, and the version byte is how the
format would change.
"""

from vault.ots.ops import TAG_SHA256
from vault.ots.tree import Node, read_node
from vault.ots.wire import FormatError, Reader

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
VERSION = 1
DIGEST_SIZE = 32


def parse_file(data: bytes) -> Node:
    """The root node of a `.ots` file, with the stored digest as message."""
    reader = Reader(data)
    if reader.take(len(MAGIC)) != MAGIC:
        raise FormatError("not an OpenTimestamps proof file")
    version = reader.byte()
    if version != VERSION:
        raise FormatError(f"unsupported proof file version {version}")
    hash_tag = reader.byte()
    if hash_tag != TAG_SHA256:
        raise FormatError(f"proof is over a 0x{hash_tag:02x} hash, not sha256")
    digest = reader.take(DIGEST_SIZE)
    root = read_node(reader, digest)
    if not reader.done():
        raise FormatError("trailing bytes after the proof")
    return root


def serialize_file(root: Node) -> bytes:
    if len(root.msg) != DIGEST_SIZE:
        raise FormatError(f"a proof file needs a {DIGEST_SIZE}-byte digest")
    return MAGIC + bytes([VERSION, TAG_SHA256]) + root.msg + root.serialize()
