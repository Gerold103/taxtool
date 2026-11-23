import os
import stat
from pathlib import Path

import pytest

from vault.errors import CorruptObjectError, HashCollisionError, VaultError
from vault.hashing import digest_bytes, digest_file
from vault.objects import ObjectStore, check_same_content


@pytest.fixture
def store(tmp_path: Path) -> ObjectStore:
    return ObjectStore(tmp_path / "vault" / "objects")


def overwrite_blob(store: ObjectStore, sha256: str, data: bytes) -> None:
    path = store.path(sha256)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    path.write_bytes(data)


async def test_put_bytes_then_get_round_trips(store: ObjectStore) -> None:
    digest = await store.put_bytes(b"hello")
    assert digest == digest_bytes(b"hello")
    assert store.has(digest.sha256)
    assert await store.get(digest.sha256) == b"hello"


async def test_put_bytes_twice_keeps_one_blob(store: ObjectStore) -> None:
    first = await store.put_bytes(b"same")
    second = await store.put_bytes(b"same")
    assert first == second
    assert list(store) == [first.sha256]


async def test_blob_path_is_sharded_and_read_only(store: ObjectStore) -> None:
    digest = await store.put_bytes(b"data")
    path = store.path(digest.sha256)
    assert path.parent.name == digest.sha256[:2]
    assert path.name == digest.sha256[2:]
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & stat.S_IWUSR == 0
    with pytest.raises(PermissionError):
        path.write_bytes(b"tamper")


async def test_put_file_copies_and_leaves_source(
    store: ObjectStore, tmp_path: Path
) -> None:
    source = tmp_path / "invoice.pdf"
    data = os.urandom(5000)
    source.write_bytes(data)
    digest = await store.put_file(source)
    assert digest == await digest_file(source)
    assert source.read_bytes() == data
    assert await store.get(digest.sha256) == data


async def test_same_content_under_two_names_is_one_blob(
    store: ObjectStore, tmp_path: Path
) -> None:
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_bytes(b"text")
    b.write_bytes(b"text")
    assert await store.put_file(a) == await store.put_file(b)
    assert len(list(store)) == 1


async def test_put_over_corrupt_blob_fails(
    store: ObjectStore, tmp_path: Path
) -> None:
    digest = await store.put_bytes(b"original")
    overwrite_blob(store, digest.sha256, b"rotten")
    with pytest.raises(CorruptObjectError) as info:
        await store.put_bytes(b"original")
    assert info.value.sha256 == digest.sha256
    assert info.value.actual == digest_bytes(b"rotten").sha256
    source = tmp_path / "original.txt"
    source.write_bytes(b"original")
    with pytest.raises(CorruptObjectError):
        await store.put_file(source)
    assert await store.get(digest.sha256) == b"rotten"


def test_check_same_content_distinguishes_collision_from_corruption(
    tmp_path: Path,
) -> None:
    # No two different inputs with one SHA-256 are known, so the collision
    # case is exercised by handing the function what it would receive from
    # a hashed incoming file: an intact blob under `sha256`, and an
    # incoming file claimed to hash to the same value.
    blob = tmp_path / "blob"
    blob.write_bytes(b"first")
    sha256 = digest_bytes(b"first").sha256
    same = tmp_path / "same"
    same.write_bytes(b"first")
    other = tmp_path / "other"
    other.write_bytes(b"second")
    check_same_content(blob, same, sha256)
    with pytest.raises(HashCollisionError) as info:
        check_same_content(blob, other, sha256)
    assert info.value.sha256 == sha256
    assert str(other) in str(info.value)
    blob.write_bytes(b"rotten")
    with pytest.raises(CorruptObjectError):
        check_same_content(blob, same, sha256)


def test_specific_errors_are_vault_errors() -> None:
    assert issubclass(CorruptObjectError, VaultError)
    assert issubclass(HashCollisionError, VaultError)


async def test_get_missing_object_fails(store: ObjectStore) -> None:
    missing = "0" * 64
    assert not store.has(missing)
    with pytest.raises(VaultError, match="no object 0000"):
        await store.get(missing)


async def test_check_passes_for_intact_blob(store: ObjectStore) -> None:
    digest = await store.put_bytes(b"intact")
    await store.check(digest.sha256)


async def test_check_detects_corrupt_blob(store: ObjectStore) -> None:
    digest = await store.put_bytes(b"original")
    overwrite_blob(store, digest.sha256, b"replaced")
    with pytest.raises(CorruptObjectError):
        await store.check(digest.sha256)


async def test_check_missing_blob_fails(store: ObjectStore) -> None:
    with pytest.raises(VaultError, match="no object"):
        await store.check("f" * 64)


async def test_iter_lists_only_blobs(store: ObjectStore) -> None:
    digests = {(await store.put_bytes(bytes([i]))).sha256 for i in range(5)}
    (store.root / "stray.txt").write_text("not a blob")
    (store.root / "ab").mkdir(exist_ok=True)
    (store.root / "ab" / "short").write_text("bad name")
    assert set(store) == digests


def test_iter_on_missing_root_is_empty(tmp_path: Path) -> None:
    assert list(ObjectStore(tmp_path / "none")) == []


async def test_no_temporary_files_remain_after_duplicates_and_errors(
    store: ObjectStore,
) -> None:
    digest = await store.put_bytes(b"a")
    await store.put_bytes(b"a")
    overwrite_blob(store, digest.sha256, b"b")
    with pytest.raises(CorruptObjectError):
        await store.put_bytes(b"a")
    leftovers = [p for p in store.root.iterdir() if p.is_file()]
    assert leftovers == []
