import shutil
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from support.local_tsa import CHAIN, DATA, LocalTsa
from vault.authorities import Authority
from vault.authorities.rfc3161 import (
    QUERY_FILE,
    TOKEN_FILE,
    Rfc3161Authority,
    parse_time,
)
from vault.errors import VaultError
from vault.hashing import digest_bytes

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl binary not installed"
)

ROOT = digest_bytes(b"root manifest").sha256
OTHER = digest_bytes(b"other").sha256


@pytest.fixture
async def tsa(tmp_path: Path) -> AsyncIterator[LocalTsa]:
    server = LocalTsa(tmp_path / "tsa")
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
def authority(tsa: LocalTsa) -> Rfc3161Authority:
    return Rfc3161Authority("testtsa", tsa.url, CHAIN)


@pytest.fixture
def proof_dir(tmp_path: Path) -> Path:
    path = tmp_path / "vault" / "seals" / "000001" / "proof" / "testtsa"
    path.mkdir(parents=True)
    return path


def test_satisfies_protocol(authority: Rfc3161Authority) -> None:
    held: Authority = authority
    assert held.name == "testtsa"


async def test_stamp_writes_query_and_token_and_verifies(
    authority: Rfc3161Authority, proof_dir: Path, tsa: LocalTsa
) -> None:
    before = datetime.now(UTC).replace(microsecond=0)
    await authority.stamp(ROOT, before, proof_dir)
    assert (proof_dir / QUERY_FILE).read_bytes() == tsa.requests[0]
    assert (proof_dir / TOKEN_FILE).stat().st_size > 1000
    stamped = await authority.verify(ROOT, proof_dir)
    assert before <= stamped <= datetime.now(UTC)


async def test_query_carries_the_root_hash_and_nothing_else(
    authority: Rfc3161Authority, proof_dir: Path, tsa: LocalTsa
) -> None:
    await authority.stamp(ROOT, datetime.now(UTC), proof_dir)
    assert bytes.fromhex(ROOT) in tsa.requests[0]
    assert len(tsa.requests[0]) < 120


async def test_committed_fixtures_are_untouched(
    authority: Rfc3161Authority, proof_dir: Path
) -> None:
    before = {p.name: p.read_bytes() for p in DATA.iterdir()}
    await authority.stamp(ROOT, datetime.now(UTC), proof_dir)
    assert {p.name: p.read_bytes() for p in DATA.iterdir()} == before


async def test_verify_rejects_other_root(
    authority: Rfc3161Authority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, datetime.now(UTC), proof_dir)
    with pytest.raises(VaultError, match="imprint mismatch"):
        await authority.verify(OTHER, proof_dir)


async def test_verify_rejects_tampered_token(
    authority: Rfc3161Authority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, datetime.now(UTC), proof_dir)
    token = proof_dir / TOKEN_FILE
    data = bytearray(token.read_bytes())
    data[-10] ^= 0xFF
    token.write_bytes(bytes(data))
    with pytest.raises(VaultError):
        await authority.verify(ROOT, proof_dir)


async def test_verify_rejects_foreign_chain(
    authority: Rfc3161Authority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, datetime.now(UTC), proof_dir)
    # The TSA's own certificate is not a trust anchor for itself.
    stranger = Rfc3161Authority("stranger", authority.url, DATA / "tsa.pem")
    with pytest.raises(VaultError, match="certificate verify error"):
        await stranger.verify(ROOT, proof_dir)


async def test_verify_without_token_or_chain_fails(
    authority: Rfc3161Authority, proof_dir: Path, tmp_path: Path
) -> None:
    with pytest.raises(VaultError, match="no proof at"):
        await authority.verify(ROOT, proof_dir)
    await authority.stamp(ROOT, datetime.now(UTC), proof_dir)
    orphan = Rfc3161Authority("x", authority.url, tmp_path / "missing.pem")
    with pytest.raises(VaultError, match="chain .* missing"):
        await orphan.verify(ROOT, proof_dir)


async def test_server_error_leaves_no_token(
    authority: Rfc3161Authority, proof_dir: Path, tsa: LocalTsa
) -> None:
    tsa.misbehave = "http500"
    with pytest.raises(VaultError, match="HTTP 500"):
        await authority.stamp(ROOT, datetime.now(UTC), proof_dir)
    assert not (proof_dir / TOKEN_FILE).exists()


async def test_garbage_reply_is_rejected(
    authority: Rfc3161Authority, proof_dir: Path, tsa: LocalTsa
) -> None:
    tsa.misbehave = "garbage"
    with pytest.raises(VaultError, match="openssl ts failed"):
        await authority.stamp(ROOT, datetime.now(UTC), proof_dir)


async def test_unreachable_server_fails(
    proof_dir: Path, tmp_path: Path
) -> None:
    server = LocalTsa(tmp_path / "tsa")
    await server.start()
    url = server.url
    await server.stop()
    authority = Rfc3161Authority("gone", url, CHAIN)
    with pytest.raises(VaultError, match="request to .* failed"):
        await authority.stamp(ROOT, datetime.now(UTC), proof_dir)


async def test_bad_root_is_rejected(
    authority: Rfc3161Authority, proof_dir: Path
) -> None:
    with pytest.raises(VaultError, match="not a sha256"):
        await authority.stamp("abc", datetime.now(UTC), proof_dir)


async def test_missing_openssl_binary_is_reported(
    tsa: LocalTsa, proof_dir: Path
) -> None:
    authority = Rfc3161Authority(
        "x", tsa.url, CHAIN, binary="openssl-does-not-exist"
    )
    with pytest.raises(VaultError, match="not found"):
        await authority.stamp(ROOT, datetime.now(UTC), proof_dir)


def test_parse_time_formats() -> None:
    text = "Status: Granted.\nTime stamp: Nov 20 19:35:37 2026 GMT\n"
    assert parse_time(text) == datetime(2026, 11, 20, 19, 35, 37, tzinfo=UTC)
    fractional = "Time stamp: Jan  5 00:00:01.250 2027 GMT"
    assert parse_time(fractional) == datetime(
        2027, 1, 5, 0, 0, 1, 250000, tzinfo=UTC
    )
    with pytest.raises(VaultError, match="no 'Time stamp'"):
        parse_time("Status: Granted.")
    with pytest.raises(VaultError, match="unreadable time"):
        parse_time("Time stamp: yesterday")
