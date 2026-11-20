import os
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from vault.authorities import Authority, check_root, check_time
from vault.authorities.local_hmac import TOKEN_FILE, LocalHmacAuthority
from vault.errors import VaultError
from vault.hashing import digest_bytes

ROOT = digest_bytes(b"root manifest").sha256
NOW = datetime(2026, 10, 4, 17, 45, tzinfo=UTC)


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / ".tax" / "authorities" / "local" / "key"
    path.parent.mkdir(parents=True)
    path.write_text(os.urandom(32).hex() + "\n")
    return path


@pytest.fixture
def authority(key_file: Path) -> LocalHmacAuthority:
    return LocalHmacAuthority("local", key_file)


@pytest.fixture
def proof_dir(tmp_path: Path) -> Path:
    path = tmp_path / ".tax" / "seals" / "000001" / "proof" / "local"
    path.mkdir(parents=True)
    return path


def rewrite_token(proof_dir: Path, **changes: object) -> None:
    path = proof_dir / TOKEN_FILE
    token = yaml.safe_load(path.read_text())
    token.update(changes)
    path.write_text(yaml.safe_dump(token))


def test_satisfies_protocol(authority: LocalHmacAuthority) -> None:
    held: Authority = authority
    assert held.name == "local"


async def test_stamp_then_verify_returns_the_time(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, NOW, proof_dir)
    assert await authority.verify(ROOT, proof_dir) == NOW


async def test_token_is_readable_yaml(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, NOW, proof_dir)
    text = (proof_dir / TOKEN_FILE).read_text()
    token = yaml.safe_load(text)
    assert token["hash"] == ROOT
    assert token["time"] == "2026-10-04T17:45:00+00:00"
    assert token["type"] == "local-hmac-sha256"
    assert len(token["mac"]) == 64
    assert all(len(line) <= 80 for line in text.splitlines())


async def test_time_is_normalised_to_utc(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    berlin = NOW.astimezone(timezone(timedelta(hours=2)))
    await authority.stamp(ROOT, berlin, proof_dir)
    token = yaml.safe_load((proof_dir / TOKEN_FILE).read_text())
    assert token["time"] == "2026-10-04T17:45:00+00:00"


async def test_naive_time_is_rejected(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    with pytest.raises(VaultError, match="timezone-aware"):
        await authority.stamp(ROOT, NOW.replace(tzinfo=None), proof_dir)


async def test_bad_root_is_rejected(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    with pytest.raises(VaultError, match="not a sha256"):
        await authority.stamp("abc", NOW, proof_dir)
    await authority.stamp(ROOT, NOW, proof_dir)
    with pytest.raises(VaultError, match="not a sha256"):
        await authority.verify("abc", proof_dir)


async def test_verify_other_root_fails(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, NOW, proof_dir)
    other = digest_bytes(b"other").sha256
    with pytest.raises(VaultError, match=f"is for hash {ROOT}"):
        await authority.verify(other, proof_dir)


async def test_tampered_time_fails(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, NOW, proof_dir)
    rewrite_token(proof_dir, time="2026-01-01T00:00:00+00:00")
    with pytest.raises(VaultError, match="invalid mac"):
        await authority.verify(ROOT, proof_dir)


async def test_tampered_mac_fails(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, NOW, proof_dir)
    rewrite_token(proof_dir, mac="0" * 64)
    with pytest.raises(VaultError, match="invalid mac"):
        await authority.verify(ROOT, proof_dir)


async def test_wrong_key_fails(
    authority: LocalHmacAuthority, proof_dir: Path, key_file: Path
) -> None:
    await authority.stamp(ROOT, NOW, proof_dir)
    key_file.write_text(os.urandom(32).hex())
    with pytest.raises(VaultError, match="invalid mac"):
        await authority.verify(ROOT, proof_dir)


async def test_missing_proof_fails(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    with pytest.raises(VaultError, match="no proof at"):
        await authority.verify(ROOT, proof_dir)


async def test_foreign_token_type_fails(
    authority: LocalHmacAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, NOW, proof_dir)
    rewrite_token(proof_dir, type="rfc3161")
    with pytest.raises(VaultError, match="is not a local-hmac"):
        await authority.verify(ROOT, proof_dir)


@pytest.mark.parametrize("content", ["", "zz", "ab" * 10])
async def test_unusable_key_file_fails(
    key_file: Path, proof_dir: Path, content: str
) -> None:
    key_file.write_text(content)
    authority = LocalHmacAuthority("local", key_file)
    with pytest.raises(VaultError, match="key"):
        await authority.stamp(ROOT, NOW, proof_dir)


async def test_missing_key_file_fails(tmp_path: Path, proof_dir: Path) -> None:
    authority = LocalHmacAuthority("local", tmp_path / "nokey")
    with pytest.raises(VaultError, match="cannot read hex key"):
        await authority.stamp(ROOT, NOW, proof_dir)


def test_check_helpers() -> None:
    assert check_root(ROOT) == ROOT
    assert check_time(NOW) == NOW
    assert check_time(NOW.astimezone(timezone(timedelta(hours=5)))) == NOW
