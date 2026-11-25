import hashlib
from pathlib import Path

import pytest

from vault.bitcoin.header import BlockHeader
from vault.ots.attestation import TAG_BITCOIN, Bitcoin
from vault.ots.file import DIGEST_SIZE, MAGIC, parse_file, serialize_file
from vault.ots.ops import TAG_APPEND, TAG_PREPEND, Op
from vault.ots.tree import Node
from vault.ots.wire import FormatError

DATA = Path(__file__).resolve().parents[2] / "support" / "data" / "ots"
PROOF = (DATA / "hello-world.txt.ots").read_bytes()
TEXT = (DATA / "hello-world.txt").read_bytes()
HEADER = BlockHeader.parse((DATA / "block-358391.bin").read_bytes())

DIGEST = hashlib.sha256(b"anything").digest()
# A proof of `DIGEST` saying only "Bitcoin block 1 has it as merkle
# root": magic, version 1, sha256 tag, the digest, one attestation.
MINIMAL = MAGIC + b"\x01\x08" + DIGEST + b"\x00" + TAG_BITCOIN + b"\x01\x01"


def test_real_proof_is_about_the_hash_of_the_text_file() -> None:
    root = parse_file(PROOF)
    assert root.msg == hashlib.sha256(TEXT).digest()


def test_real_proof_ends_in_the_merkle_root_of_its_block() -> None:
    root = parse_file(PROOF)
    attestations = list(root.all_attestations())
    assert len(attestations) == 1
    node, attestation = attestations[0]
    assert attestation == Bitcoin(358391)
    assert node.msg == HEADER.merkle_root


def test_real_proof_round_trips_to_the_identical_bytes() -> None:
    assert serialize_file(parse_file(PROOF)) == PROOF
    assert len(PROOF) == 688


def test_altering_one_sibling_hash_breaks_the_chain() -> None:
    root = parse_file(PROOF)
    node, op = next(
        (node, op)
        for node in root.walk()
        for op in node.ops
        if op.tag in (TAG_APPEND, TAG_PREPEND)
    )
    altered = Op(op.tag, bytes([op.arg[0] ^ 1]) + op.arg[1:])
    node.ops[altered] = node.ops.pop(op)
    # Only the first message is stored, so reparsing recomputes the rest
    # from the altered sibling and the chain ends somewhere else.
    reparsed = parse_file(serialize_file(root))
    (final, _), *_ = reparsed.all_attestations()
    assert final.msg != HEADER.merkle_root


def test_minimal_file_parses_and_serializes_by_hand() -> None:
    root = parse_file(MINIMAL)
    assert root == Node(DIGEST, {Bitcoin(1)})
    assert serialize_file(root) == MINIMAL


def test_wrong_magic_is_refused() -> None:
    bad = b"\x00OpenTimestamps\x00\x00Proof\x00" + b"\x00" * 8 + MINIMAL[31:]
    with pytest.raises(FormatError, match="not an OpenTimestamps proof file"):
        parse_file(bad)


def test_other_version_is_refused() -> None:
    bad = MAGIC + b"\x02" + MINIMAL[len(MAGIC) + 1 :]
    with pytest.raises(FormatError, match="unsupported proof file version 2"):
        parse_file(bad)


def test_other_hash_is_refused() -> None:
    bad = MAGIC + b"\x01\x02" + MINIMAL[len(MAGIC) + 2 :]
    with pytest.raises(FormatError, match="over a 0x02 hash, not sha256"):
        parse_file(bad)


def test_truncated_digest_is_refused() -> None:
    cut = MAGIC + b"\x01\x08" + DIGEST[:-1]
    with pytest.raises(FormatError, match="wanted 32 bytes at offset 33"):
        parse_file(cut)


def test_trailing_bytes_are_refused() -> None:
    with pytest.raises(FormatError, match="trailing bytes after the proof"):
        parse_file(MINIMAL + b"\x00")


def test_file_needs_a_sha256_sized_digest() -> None:
    with pytest.raises(FormatError, match=f"{DIGEST_SIZE}-byte digest"):
        serialize_file(Node(b"short", {Bitcoin(1)}))
