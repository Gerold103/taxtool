"""The proof tree.

A proof starts at one message, our digest, and every operation leads
from a message to the message it produces. Usually that is a single
path, from the digest through the calendar's merkle tree, the
transaction and the block's merkle tree to the block's merkle root.
It becomes a tree when the same digest was sent to several calendars,
or where a node both carries an attestation and leads on: after
completion the commitment node keeps its pending attestation while an
operation continues from it toward the block.

A node therefore is a message, the attestations made directly about
it, and the operations leading on from it. Only the first message is
ever stored; every other one is recomputed by applying the operations,
which is also what makes a proof unforgeable without inverting a hash.

Attestations are a set because the format allows several parties to
vouch for one message and the reference stores them so. In practice a
node has one or none: the commitment node its pending attestation, the
final node its Bitcoin one. Keeping the set means any legal proof file
round-trips through this code unchanged.

On the wire a node lists its elements, every one but the last preceded
by 0xff: an attestation as 0x00 and the attestation, an operation as
the operation followed by the node it leads to.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field

from vault.ots.attestation import (
    Attestation,
    parse_attestation,
    serialize_attestation,
    sort_key,
)
from vault.ots.ops import Op, parse_op
from vault.ots.wire import FormatError, Reader

TAG_ATTESTATION = 0x00
TAG_BRANCH = 0xFF
# The reference stops recursing here; real proofs are a few dozen deep.
MAX_DEPTH = 256


@dataclass
class Node:
    """One message of a proof, what is said about it, and what follows."""

    msg: bytes
    attestations: set[Attestation] = field(default_factory=set)
    ops: dict[Op, "Node"] = field(default_factory=dict)

    def step(self, op: Op) -> "Node":
        """The node `op` leads to, created if this is the first time."""
        following = self.ops.get(op)
        if following is None:
            following = Node(op.apply(self.msg))
            self.ops[op] = following
        return following

    def merge(self, other: "Node") -> None:
        """Take over everything `other` says about the same message."""
        if other.msg != self.msg:
            raise FormatError("cannot merge proofs of different messages")
        self.attestations |= other.attestations
        for op, following in other.ops.items():
            self.step(op).merge(following)

    def walk(self) -> Iterator["Node"]:
        """This node and every node reachable from it."""
        yield self
        for following in self.ops.values():
            yield from following.walk()

    def all_attestations(self) -> Iterator[tuple["Node", Attestation]]:
        """Every attestation in the tree with the node it is about."""
        for node in self.walk():
            for attestation in sorted(node.attestations, key=sort_key):
                yield node, attestation

    def serialize(self) -> bytes:
        attestations = sorted(self.attestations, key=sort_key)
        ops = sorted(self.ops.items())
        if not attestations and not ops:
            raise FormatError("a node without attestations or operations")
        elements = [
            bytes([TAG_ATTESTATION]) + serialize_attestation(a)
            for a in attestations
        ]
        elements += [op.serialize() + node.serialize() for op, node in ops]
        branch = bytes([TAG_BRANCH])
        return b"".join(branch + e for e in elements[:-1]) + elements[-1]


def read_node(reader: Reader, msg: bytes, depth: int = MAX_DEPTH) -> Node:
    """The node for `msg` at the reader's position, with everything that
    follows from it; the reader is left after it."""
    if depth == 0:
        raise FormatError(f"proof nested deeper than {MAX_DEPTH}")
    node = Node(msg)
    while True:
        tag = reader.byte()
        last = tag != TAG_BRANCH
        if not last:
            tag = reader.byte()
        if tag == TAG_ATTESTATION:
            node.attestations.add(parse_attestation(reader))
        else:
            op = parse_op(reader, tag)
            if op in node.ops:
                raise FormatError(f"operation {op} repeated in one node")
            node.ops[op] = read_node(reader, op.apply(msg), depth - 1)
        if last:
            return node


def parse_node(data: bytes, msg: bytes) -> Node:
    """A serialized node for `msg`, the whole buffer and nothing more."""
    reader = Reader(data)
    node = read_node(reader, msg)
    if not reader.done():
        raise FormatError("trailing bytes after the proof")
    return node
