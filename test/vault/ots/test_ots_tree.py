import hashlib

import pytest

from vault.ots.attestation import TAG_BITCOIN, TAG_PENDING, Bitcoin, Pending
from vault.ots.ops import TAG_APPEND, TAG_PREPEND, TAG_SHA256, Op
from vault.ots.tree import MAX_DEPTH, Node, parse_node
from vault.ots.wire import FormatError

MSG = b"hello"
SHA256 = Op(TAG_SHA256)
# The attestations as they appear on the wire, each after its 0x00.
BITCOIN_1 = b"\x00" + TAG_BITCOIN + b"\x01\x01"
PENDING_AB = b"\x00" + TAG_PENDING + b"\x0c\x0bhttps://a.b"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def test_single_attestation_is_marker_then_attestation() -> None:
    node = Node(MSG, {Bitcoin(1)})
    assert node.serialize() == BITCOIN_1
    assert parse_node(BITCOIN_1, MSG) == node


def test_path_is_operation_then_the_node_it_leads_to() -> None:
    node = Node(MSG)
    node.step(SHA256).attestations.add(Bitcoin(1))
    data = b"\x08" + BITCOIN_1
    assert node.serialize() == data
    parsed = parse_node(data, MSG)
    assert parsed == node
    assert parsed.ops[SHA256].msg == sha256(MSG)


def test_every_element_but_the_last_is_preceded_by_a_branch_byte() -> None:
    node = Node(MSG, {Pending("https://a.b")})
    node.step(SHA256).attestations.add(Bitcoin(1))
    data = b"\xff" + PENDING_AB + b"\x08" + BITCOIN_1
    assert node.serialize() == data
    assert parse_node(data, MSG) == node


def test_operations_are_written_in_sorted_order() -> None:
    node = Node(MSG)
    node.step(Op(TAG_PREPEND, b"b")).attestations.add(Bitcoin(1))
    node.step(Op(TAG_APPEND, b"a")).attestations.add(Bitcoin(1))
    data = b"\xff\xf0\x01a" + BITCOIN_1 + b"\xf1\x01b" + BITCOIN_1
    assert node.serialize() == data
    assert parse_node(data, MSG) == node


def test_step_computes_the_message_and_reuses_the_node() -> None:
    node = Node(MSG)
    following = node.step(Op(TAG_APPEND, b"!"))
    assert following.msg == b"hello!"
    assert node.step(Op(TAG_APPEND, b"!")) is following


def test_merge_takes_over_attestations_and_paths() -> None:
    ours = Node(MSG, {Pending("https://a.b")})
    theirs = Node(MSG)
    theirs.step(SHA256).attestations.add(Bitcoin(1))
    ours.merge(theirs)
    assert ours.attestations == {Pending("https://a.b")}
    assert ours.ops[SHA256].attestations == {Bitcoin(1)}


def test_merge_grafts_onto_a_node_deeper_in_the_tree() -> None:
    ours = Node(MSG)
    commitment = ours.step(SHA256)
    commitment.attestations.add(Pending("https://a.b"))
    answer = Node(commitment.msg)
    answer.step(Op(TAG_APPEND, b"x")).attestations.add(Bitcoin(1))
    commitment.merge(answer)
    assert list(ours.all_attestations()) == [
        (commitment, Pending("https://a.b")),
        (commitment.ops[Op(TAG_APPEND, b"x")], Bitcoin(1)),
    ]


def test_merge_of_a_different_message_is_refused() -> None:
    with pytest.raises(FormatError, match="different messages"):
        Node(MSG).merge(Node(b"other"))


def test_walk_visits_every_node_once() -> None:
    node = Node(MSG)
    node.step(SHA256).step(SHA256)
    node.step(Op(TAG_APPEND, b"x"))
    assert [n.msg for n in node.walk()] == [
        MSG,
        sha256(MSG),
        sha256(sha256(MSG)),
        MSG + b"x",
    ]


def test_empty_node_cannot_be_serialized() -> None:
    with pytest.raises(FormatError, match="without attestations or operations"):
        Node(MSG).serialize()


def test_repeated_operation_in_one_node_is_refused() -> None:
    data = b"\xff\x08" + BITCOIN_1 + b"\x08" + BITCOIN_1
    with pytest.raises(FormatError, match="repeated in one node"):
        parse_node(data, MSG)


def test_branch_byte_followed_by_branch_byte_is_refused() -> None:
    with pytest.raises(FormatError, match="unknown operation tag 0xff"):
        parse_node(b"\xff\xff" + BITCOIN_1, MSG)


def test_trailing_bytes_are_refused() -> None:
    with pytest.raises(FormatError, match="trailing bytes"):
        parse_node(BITCOIN_1 + b"\x00", MSG)


def test_depth_limit_allows_the_reference_depth() -> None:
    data = b"\x08" * (MAX_DEPTH - 1) + BITCOIN_1
    node = parse_node(data, MSG)
    assert len(list(node.walk())) == MAX_DEPTH
    assert node.serialize() == data


def test_depth_limit_refuses_one_more() -> None:
    data = b"\x08" * MAX_DEPTH + BITCOIN_1
    with pytest.raises(FormatError, match=f"deeper than {MAX_DEPTH}"):
        parse_node(data, MSG)
