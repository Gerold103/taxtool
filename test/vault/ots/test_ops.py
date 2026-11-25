import hashlib

import pytest

from vault.ots.ops import (
    MAX_LENGTH,
    TAG_APPEND,
    TAG_PREPEND,
    TAG_RIPEMD160,
    TAG_SHA1,
    TAG_SHA256,
    Op,
    parse_op,
)
from vault.ots.wire import FormatError, Reader

MSG = b"hello"


@pytest.mark.parametrize(
    ("tag", "name"),
    [(TAG_SHA1, "sha1"), (TAG_RIPEMD160, "ripemd160"), (TAG_SHA256, "sha256")],
)
def test_hash_op_applies_the_named_hash(tag: int, name: str) -> None:
    assert Op(tag).apply(MSG) == hashlib.new(name, MSG).digest()


def test_append_and_prepend_add_on_the_named_side() -> None:
    assert Op(TAG_APPEND, b"!").apply(MSG) == b"hello!"
    assert Op(TAG_PREPEND, b">").apply(MSG) == b">hello"


def test_hash_op_serializes_as_its_tag_alone() -> None:
    assert Op(TAG_SHA256).serialize() == b"\x08"


def test_append_serializes_as_tag_then_varbytes() -> None:
    assert Op(TAG_APPEND, b"abc").serialize() == b"\xf0\x03abc"
    assert Op(TAG_PREPEND, b"abc").serialize() == b"\xf1\x03abc"


@pytest.mark.parametrize(
    "op",
    [
        Op(TAG_SHA1),
        Op(TAG_SHA256),
        Op(TAG_APPEND, b"\x00"),
        Op(TAG_PREPEND, b"x" * MAX_LENGTH),
    ],
)
def test_op_round_trips(op: Op) -> None:
    reader = Reader(op.serialize())
    tag = reader.byte()
    assert parse_op(reader, tag) == op
    assert reader.done()


def test_unknown_tag_is_refused() -> None:
    with pytest.raises(FormatError, match="unknown operation tag 0x01"):
        parse_op(Reader(b""), 0x01)


def test_empty_append_is_refused() -> None:
    with pytest.raises(FormatError, match="length 0 out of range"):
        parse_op(Reader(b"\x00"), TAG_APPEND)


def test_overlong_append_is_refused_before_reading() -> None:
    reader = Reader(Op(TAG_APPEND, b"x" * (MAX_LENGTH + 1)).serialize()[1:])
    with pytest.raises(
        FormatError, match=f"length {MAX_LENGTH + 1} out of range"
    ):
        parse_op(reader, TAG_APPEND)


def test_overlong_message_is_refused() -> None:
    with pytest.raises(FormatError, match="message of 4097 bytes is too long"):
        Op(TAG_SHA256).apply(b"x" * (MAX_LENGTH + 1))


def test_overlong_result_is_refused() -> None:
    with pytest.raises(FormatError, match="result of 4097 bytes is too long"):
        Op(TAG_APPEND, b"!").apply(b"x" * MAX_LENGTH)


def test_ops_sort_by_tag_then_argument() -> None:
    ops = [
        Op(TAG_PREPEND, b"a"),
        Op(TAG_APPEND, b"b"),
        Op(TAG_APPEND, b"a"),
        Op(TAG_SHA256),
    ]
    assert sorted(ops) == [
        Op(TAG_SHA256),
        Op(TAG_APPEND, b"a"),
        Op(TAG_APPEND, b"b"),
        Op(TAG_PREPEND, b"a"),
    ]
