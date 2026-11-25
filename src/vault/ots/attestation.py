"""Attestations: statements attached to a node of a proof about the
message that node holds.

Two kinds are known. Pending: "the calendar at this URI holds the
message and will anchor it later". Bitcoin: "the Bitcoin block at this
height has the message as its merkle root". Any other kind is kept as
the raw tag and payload it arrived with and written back unchanged, as
the reference implementation does, so that a proof carrying, say, a
Litecoin attestation survives a round trip through this code.

On the wire an attestation is an 8-byte tag naming the kind, then its
payload as a byte string. The tags are the reference implementation's
and consensus critical.
"""

from dataclasses import dataclass

from vault.ots.wire import FormatError, Reader, varbytes, varuint

TAG_SIZE = 8
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")

MAX_PAYLOAD = 8192
MAX_URI = 1000
MAX_HEIGHT = 2**32 - 1
# The reference allows nothing else in a calendar URI: no query, no
# fragment, no credentials, no percent escapes.
URI_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:"
)


@dataclass(frozen=True, order=True)
class Pending:
    """The calendar at `uri` holds the message; ask it later."""

    uri: str

    def payload(self) -> bytes:
        return varbytes(self.uri.encode())


@dataclass(frozen=True, order=True)
class Bitcoin:
    """The Bitcoin block at `height` has the message as merkle root."""

    height: int

    def payload(self) -> bytes:
        return varuint(self.height)


@dataclass(frozen=True, order=True)
class Unknown:
    """A kind this code does not know, carried through untouched."""

    tag: bytes
    raw_payload: bytes

    def payload(self) -> bytes:
        return self.raw_payload


type Attestation = Pending | Bitcoin | Unknown


def tag_of(attestation: Attestation) -> bytes:
    match attestation:
        case Pending():
            return TAG_PENDING
        case Bitcoin():
            return TAG_BITCOIN
        case Unknown():
            return attestation.tag


def sort_key(attestation: Attestation) -> tuple[bytes, bytes]:
    """The reference orders attestations by tag, then payload."""
    return tag_of(attestation), attestation.payload()


def serialize_attestation(attestation: Attestation) -> bytes:
    return tag_of(attestation) + varbytes(attestation.payload())


def _parse_pending(payload: Reader) -> Pending:
    uri = payload.varbytes(MAX_URI).decode(errors="replace")
    if not set(uri) <= URI_CHARS:
        raise FormatError(f"invalid calendar uri {uri!r}")
    return Pending(uri)


def _parse_bitcoin(payload: Reader) -> Bitcoin:
    height = payload.varuint()
    if height > MAX_HEIGHT:
        raise FormatError(f"block height {height} is too large")
    return Bitcoin(height)


def parse_attestation(reader: Reader) -> Attestation:
    """An attestation whose 0x00 marker byte was already read."""
    tag = reader.take(TAG_SIZE)
    raw = reader.varbytes(MAX_PAYLOAD)
    payload = Reader(raw)
    if tag == TAG_PENDING:
        attestation: Attestation = _parse_pending(payload)
    elif tag == TAG_BITCOIN:
        attestation = _parse_bitcoin(payload)
    else:
        return Unknown(tag, raw)
    if not payload.done():
        raise FormatError("trailing bytes in an attestation")
    return attestation
