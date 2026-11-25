import pytest

from vault.ots.wire import (
    MAX_VARUINT_BYTES,
    FormatError,
    Reader,
    varbytes,
    varuint,
)

# Values and encodings from the LEB128 article and the reference's own
# test vectors: 300 is the textbook example, 0xac 0x02.
VARUINTS = [
    (0, b"\x00"),
    (1, b"\x01"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (300, b"\xac\x02"),
    (2**32 - 1, b"\xff\xff\xff\xff\x0f"),
    (2**63 - 1, b"\xff" * 8 + b"\x7f"),
]


@pytest.mark.parametrize(("value", "encoded"), VARUINTS)
def test_varuint_encodes_as_leb128(value: int, encoded: bytes) -> None:
    assert varuint(value) == encoded


@pytest.mark.parametrize(("value", "encoded"), VARUINTS)
def test_varuint_round_trips(value: int, encoded: bytes) -> None:
    reader = Reader(encoded)
    assert reader.varuint() == value
    assert reader.done()


def test_varuint_longer_than_nine_bytes_is_refused() -> None:
    reader = Reader(b"\x80" * MAX_VARUINT_BYTES + b"\x01")
    with pytest.raises(FormatError, match="longer than 9 bytes"):
        reader.varuint()


def test_varuint_cut_off_mid_number_is_truncated() -> None:
    with pytest.raises(
        FormatError, match="truncated: wanted 1 bytes at offset 1"
    ):
        Reader(b"\x80").varuint()


def test_varbytes_is_length_then_bytes() -> None:
    assert varbytes(b"") == b"\x00"
    assert varbytes(b"abc") == b"\x03abc"
    assert varbytes(b"x" * 200) == b"\xc8\x01" + b"x" * 200


def test_varbytes_round_trips() -> None:
    data = bytes(range(256))
    reader = Reader(varbytes(data))
    assert reader.varbytes(max_length=256) == data
    assert reader.done()


def test_varbytes_above_maximum_is_refused_before_reading() -> None:
    reader = Reader(b"\x05abcde")
    with pytest.raises(FormatError, match="length 5 out of range"):
        reader.varbytes(max_length=4)


def test_varbytes_below_minimum_is_refused() -> None:
    reader = Reader(b"\x00")
    with pytest.raises(FormatError, match="length 0 out of range"):
        reader.varbytes(max_length=10, min_length=1)


def test_varbytes_shorter_than_announced_is_truncated() -> None:
    reader = Reader(b"\x05abc")
    with pytest.raises(FormatError, match="truncated: wanted 5 bytes"):
        reader.varbytes(max_length=10)


def test_reader_walks_the_buffer() -> None:
    reader = Reader(b"\x01\x02\x03")
    assert reader.byte() == 1
    assert reader.take(2) == b"\x02\x03"
    assert reader.done()


def test_reader_reports_the_offset_of_the_shortfall() -> None:
    reader = Reader(b"\x01\x02\x03")
    reader.take(2)
    with pytest.raises(FormatError, match="wanted 2 bytes at offset 2"):
        reader.take(2)


def test_reader_is_not_done_with_bytes_left() -> None:
    reader = Reader(b"\x01\x02")
    reader.byte()
    assert not reader.done()
