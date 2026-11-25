import pytest

from vault.ots.attestation import (
    MAX_HEIGHT,
    MAX_PAYLOAD,
    MAX_URI,
    TAG_BITCOIN,
    TAG_PENDING,
    Attestation,
    Bitcoin,
    Pending,
    Unknown,
    parse_attestation,
    serialize_attestation,
    sort_key,
)
from vault.ots.wire import FormatError, Reader, varbytes

URI = "https://a.b"
HEIGHT = 358391


def test_pending_is_tag_then_payload_holding_the_uri_as_varbytes() -> None:
    # The URI is 11 bytes; as varbytes it is 12, and that is the payload.
    assert serialize_attestation(Pending(URI)) == (
        TAG_PENDING + b"\x0c" + b"\x0bhttps://a.b"
    )


def test_bitcoin_is_tag_then_payload_holding_the_height_as_varuint() -> None:
    # 358391 in LEB128 is f7 ef 15, three bytes.
    assert serialize_attestation(Bitcoin(HEIGHT)) == (
        TAG_BITCOIN + b"\x03\xf7\xef\x15"
    )


@pytest.mark.parametrize(
    "attestation",
    [
        Pending(URI),
        Pending("a" * MAX_URI),
        Bitcoin(0),
        Bitcoin(HEIGHT),
        Bitcoin(MAX_HEIGHT),
        Unknown(b"\x01" * 8, b""),
        Unknown(b"\x01" * 8, b"anything \x00\xff goes"),
    ],
)
def test_attestation_round_trips(attestation: Attestation) -> None:
    reader = Reader(serialize_attestation(attestation))
    assert parse_attestation(reader) == attestation
    assert reader.done()


def test_unknown_kind_keeps_its_bytes() -> None:
    raw = b"\x06\xa3\xe3\x88\x6c\x4c\x29\x8e" + varbytes(b"\x05")
    attestation = parse_attestation(Reader(raw))
    assert isinstance(attestation, Unknown)
    assert serialize_attestation(attestation) == raw


def test_uri_with_a_query_is_refused() -> None:
    bad = TAG_PENDING + varbytes(varbytes(b"https://a.b/?x=1"))
    with pytest.raises(FormatError, match="invalid calendar uri"):
        parse_attestation(Reader(bad))


def test_overlong_uri_is_refused() -> None:
    bad = TAG_PENDING + varbytes(varbytes(b"a" * (MAX_URI + 1)))
    with pytest.raises(FormatError, match=f"length {MAX_URI + 1} out of range"):
        parse_attestation(Reader(bad))


def test_height_above_32_bits_is_refused() -> None:
    bad = TAG_BITCOIN + varbytes(b"\x80\x80\x80\x80\x10")
    with pytest.raises(FormatError, match="block height 4294967296 is too"):
        parse_attestation(Reader(bad))


def test_trailing_bytes_in_a_known_payload_are_refused() -> None:
    bad = TAG_BITCOIN + varbytes(b"\x01\x00")
    with pytest.raises(FormatError, match="trailing bytes in an attestation"):
        parse_attestation(Reader(bad))


def test_overlong_payload_is_refused_before_reading() -> None:
    bad = TAG_BITCOIN + varbytes(b"\x00" * (MAX_PAYLOAD + 1))
    with pytest.raises(
        FormatError, match=f"length {MAX_PAYLOAD + 1} out of range"
    ):
        parse_attestation(Reader(bad))


def test_short_tag_is_truncated() -> None:
    with pytest.raises(FormatError, match="wanted 8 bytes at offset 0"):
        parse_attestation(Reader(TAG_BITCOIN[:7]))


def test_bitcoin_sorts_before_pending() -> None:
    assert TAG_BITCOIN < TAG_PENDING
    attestations: list[Attestation] = [Pending(URI), Bitcoin(2), Bitcoin(1)]
    assert sorted(attestations, key=sort_key) == [
        Bitcoin(1),
        Bitcoin(2),
        Pending(URI),
    ]
