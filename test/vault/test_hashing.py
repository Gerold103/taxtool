import hashlib
import os
from pathlib import Path

import pytest

from vault.errors import VaultError
from vault.hashing import (
    CHUNK_SIZE,
    Digest,
    blob_relpath,
    digest_bytes,
    digest_file,
    digest_prefix,
    is_sha256_hex,
)

EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


@pytest.mark.parametrize(
    ("data", "expected"),
    [(b"", Digest(EMPTY, 0)), (b"abc", Digest(ABC, 3))],
)
def test_digest_bytes_matches_known_vectors(
    data: bytes, expected: Digest
) -> None:
    assert digest_bytes(data) == expected


async def test_digest_file_equals_digest_of_its_bytes(tmp_path: Path) -> None:
    path = tmp_path / "doc.bin"
    data = os.urandom(3 * CHUNK_SIZE + 17)
    path.write_bytes(data)
    assert await digest_file(path) == digest_bytes(data)


async def test_digest_file_of_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty"
    path.touch()
    assert await digest_file(path) == Digest(EMPTY, 0)


async def test_digest_prefix_hashes_only_the_prefix(tmp_path: Path) -> None:
    path = tmp_path / "log.yaml"
    data = os.urandom(CHUNK_SIZE + 100)
    path.write_bytes(data)
    length = CHUNK_SIZE + 1
    expected = hashlib.sha256(data[:length]).hexdigest()
    assert await digest_prefix(path, length) == Digest(expected, length)


async def test_digest_prefix_of_whole_file_equals_file_digest(
    tmp_path: Path,
) -> None:
    path = tmp_path / "log.yaml"
    path.write_bytes(b"version: 1\n")
    whole = await digest_file(path)
    assert await digest_prefix(path, whole.size) == whole


async def test_digest_prefix_longer_than_file_fails(tmp_path: Path) -> None:
    path = tmp_path / "short"
    path.write_bytes(b"12345")
    with pytest.raises(VaultError, match="at least 6 bytes.*has 5"):
        await digest_prefix(path, 6)


async def test_digest_prefix_negative_length_fails(tmp_path: Path) -> None:
    path = tmp_path / "any"
    path.write_bytes(b"x")
    with pytest.raises(VaultError, match="negative"):
        await digest_prefix(path, -1)


async def test_digest_file_missing_raises_os_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        await digest_file(tmp_path / "nope")


def test_blob_relpath_splits_two_and_sixty_two() -> None:
    assert blob_relpath(ABC) == Path("ba") / ABC[2:]


@pytest.mark.parametrize("bad", ["", "abc", ABC.upper(), ABC + "0", "g" * 64])
def test_blob_relpath_rejects_non_digests(bad: str) -> None:
    assert not is_sha256_hex(bad)
    with pytest.raises(VaultError, match="not a sha256"):
        blob_relpath(bad)
