from datetime import UTC, datetime
from pathlib import Path

import pytest

from vault.bitcoin.header import SIZE, BlockHeader
from vault.errors import VaultError

DATA = Path(__file__).resolve().parents[2] / "support" / "data" / "ots"
HEADER_358391 = DATA / "block-358391.bin"
HASH_358391 = "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"
# The genesis block, from any explorer; its bits 0x1d00ffff are the
# textbook example of the compact target encoding.
GENESIS = bytes.fromhex(
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49"
    "ffff001d"
    "1dac2b7c"
)
GENESIS_HASH = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)


def test_real_header_parses_hashes_and_passes_proof_of_work() -> None:
    header = BlockHeader.parse(HEADER_358391.read_bytes())
    assert header.hash == HASH_358391
    assert header.time == datetime(2015, 5, 28, 15, 41, 18, tzinfo=UTC)
    assert header.version == 2
    assert header.raw == HEADER_358391.read_bytes()
    header.check()


def test_genesis_block_target_is_the_textbook_value() -> None:
    header = BlockHeader.parse(GENESIS)
    assert header.hash == GENESIS_HASH
    assert header.bits == 0x1D00FFFF
    assert header.target == 0x00FFFF << (8 * (0x1D - 3))
    assert header.target == int("00000000ffff" + "0" * 52, 16)
    header.check()
    assert header.time == datetime(2009, 1, 3, 18, 15, 5, tzinfo=UTC)


def test_merkle_root_is_in_internal_byte_order() -> None:
    header = BlockHeader.parse(GENESIS)
    displayed = (
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    )
    assert header.merkle_root[::-1].hex() == displayed


@pytest.mark.parametrize("length", [0, SIZE - 1, SIZE + 1])
def test_wrong_length_is_rejected(length: int) -> None:
    with pytest.raises(VaultError, match=f"has {length} bytes, not {SIZE}"):
        BlockHeader.parse(b"\0" * length)


def test_altered_header_fails_proof_of_work() -> None:
    raw = bytearray(HEADER_358391.read_bytes())
    raw[-1] ^= 1
    with pytest.raises(VaultError, match="proof of work"):
        BlockHeader.parse(bytes(raw)).check()
