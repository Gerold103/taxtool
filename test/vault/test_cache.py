import os
import time
from pathlib import Path

import pytest

from vault.cache import (
    CACHE_HEADER,
    CacheEntry,
    StatCache,
    load_stat_cache,
    save_stat_cache,
)
from vault.errors import VaultError
from vault.hashing import Digest, digest_bytes
from vault.scan import scan_files

A = digest_bytes(b"aaaa")
B = digest_bytes(b"bbbb")


def write(root: Path, rel: str, data: bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def set_mtime(path: Path, mtime_ns: int) -> None:
    os.utime(path, ns=(mtime_ns, mtime_ns))


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    return tmp_path / "state" / "cache" / "tree"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    write(root, "a.txt", b"aaaa")
    write(root, "docs/with space.pdf", b"bbbb")
    return root


async def test_scan_creates_the_cache_with_every_file(
    root: Path, cache: Path
) -> None:
    manifest = await scan_files(root, cache=cache)
    assert manifest.files == {"a.txt": A, "docs/with space.pdf": B}
    saved = load_stat_cache(cache)
    assert saved.entries == {
        "a.txt": CacheEntry(4, (root / "a.txt").stat().st_mtime_ns, A.sha256),
        "docs/with space.pdf": CacheEntry(
            4, (root / "docs/with space.pdf").stat().st_mtime_ns, B.sha256
        ),
    }
    assert saved.started_ns <= time.time_ns()


async def test_second_scan_reuses_digests_of_unchanged_files(
    root: Path, cache: Path
) -> None:
    first = await scan_files(root, cache=cache)
    # Same size and mtime as before means the cache answers without
    # reading the file. That is the whole point, and also the one way
    # to defeat the cache; a scan without one hashes everything.
    path = root / "a.txt"
    mtime_ns = path.stat().st_mtime_ns
    path.write_bytes(b"zzzz")
    set_mtime(path, mtime_ns)
    assert await scan_files(root, cache=cache) == first
    assert (await scan_files(root)).files["a.txt"] == digest_bytes(b"zzzz")


async def test_changed_mtime_or_size_triggers_a_rehash(
    root: Path, cache: Path
) -> None:
    await scan_files(root, cache=cache)
    path = root / "a.txt"
    mtime_ns = path.stat().st_mtime_ns
    path.write_bytes(b"zzzz")
    set_mtime(path, mtime_ns + 1)
    assert (await scan_files(root, cache=cache)).files["a.txt"] == digest_bytes(
        b"zzzz"
    )
    path.write_bytes(b"longer")
    set_mtime(path, mtime_ns + 1)
    assert (await scan_files(root, cache=cache)).files["a.txt"] == digest_bytes(
        b"longer"
    )


async def test_added_and_deleted_files_update_the_cache(
    root: Path, cache: Path
) -> None:
    await scan_files(root, cache=cache)
    (root / "a.txt").unlink()
    write(root, "new.txt", b"new")
    manifest = await scan_files(root, cache=cache)
    assert set(manifest.files) == {"docs/with space.pdf", "new.txt"}
    assert set(load_stat_cache(cache).entries) == set(manifest.files)


def test_entry_written_in_the_scan_window_is_not_trusted(
    tmp_path: Path,
) -> None:
    path = write(tmp_path, "a", b"aaaa")
    st = path.stat()
    entry = CacheEntry(st.st_size, st.st_mtime_ns, A.sha256)
    trusted = StatCache(st.st_mtime_ns + 1, {"a": entry})
    assert trusted.lookup("a", st) == Digest(A.sha256, 4)
    racy = StatCache(st.st_mtime_ns, {"a": entry})
    assert racy.lookup("a", st) is None
    assert trusted.lookup("other", st) is None


def test_save_and_load_round_trip(cache: Path) -> None:
    original = StatCache(
        123456789,
        {
            "docs/with space.pdf": CacheEntry(4, 99, B.sha256),
            "a": CacheEntry(1, 2, A.sha256),
        },
    )
    save_stat_cache(cache, original)
    assert load_stat_cache(cache) == original
    lines = cache.read_text().splitlines()
    assert lines[0] == f"{CACHE_HEADER} 1 123456789"
    assert lines[1].endswith(" a")
    assert lines[2].endswith(" docs/with space.pdf")


def test_missing_cache_is_empty(cache: Path) -> None:
    assert load_stat_cache(cache) == StatCache()


@pytest.mark.parametrize(
    "text",
    [
        "",
        "something-else 1 0\n",
        f"{CACHE_HEADER} 2 0\n",
        f"{CACHE_HEADER} 1 0\nnot-a-digest 4 5 a\n",
        f"{CACHE_HEADER} 1 0\n{A.sha256} four 5 a\n",
        f"{CACHE_HEADER} 1 0\n{A.sha256} 4 5 ../escape\n",
        f"{CACHE_HEADER} 1 0\n{A.sha256} 4\n",
    ],
)
def test_malformed_cache_is_reported_with_its_path(
    cache: Path, text: str
) -> None:
    cache.parent.mkdir(parents=True)
    cache.write_text(text)
    with pytest.raises(VaultError, match=f"{cache}.*delete it"):
        load_stat_cache(cache)


async def test_cache_file_is_not_part_of_the_tree_unless_inside(
    root: Path, cache: Path
) -> None:
    manifest = await scan_files(root, cache=cache)
    assert "cache/tree" not in str(list(manifest.files))
    inside = root / "state" / "cache" / "tree"
    manifest = await scan_files(root, exclude={"state"}, cache=inside)
    assert set(manifest.files) == {"a.txt", "docs/with space.pdf"}
