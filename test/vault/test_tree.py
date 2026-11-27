import os
import stat
from pathlib import Path

import pytest

from vault.errors import CorruptObjectError, VaultError
from vault.hashing import Digest, digest_bytes
from vault.manifest import Manifest
from vault.objects import ObjectStore
from vault.tree import (
    EntryKind,
    Tree,
    TreeEntry,
    check_path_component,
    read_tree,
    write_tree,
)

A = digest_bytes(b"a")
B = digest_bytes(b"b")
C = digest_bytes(b"c")


@pytest.fixture
def store(tmp_path: Path) -> ObjectStore:
    return ObjectStore(tmp_path / "vault" / "objects")


async def test_write_then_read_round_trips(store: ObjectStore) -> None:
    manifest = Manifest(
        {
            "config.yaml": A,
            "docs/2026/inv-001.pdf": B,
            "docs/2026/inv-001.txt": C,
            "log/log_00001.yaml": A,
        }
    )
    root = await write_tree(store, manifest)
    assert await read_tree(store, root) == manifest


async def test_root_is_the_digest_of_the_root_listing(
    store: ObjectStore,
) -> None:
    root = await write_tree(store, Manifest({"docs/x.pdf": A}))
    data = await store.get(root.sha256)
    assert digest_bytes(data) == root
    leaf = Tree({"x.pdf": TreeEntry(EntryKind.FILE, A)}).to_yaml().encode()
    assert Tree.from_yaml(data.decode()).entries == {
        "docs": TreeEntry(EntryKind.TREE, digest_bytes(leaf))
    }


async def test_one_object_per_directory(store: ObjectStore) -> None:
    await write_tree(store, Manifest({"a/x": A, "b/y": B, "z": C}))
    assert len(list(store)) == 3


async def test_unchanged_subtrees_are_shared(store: ObjectStore) -> None:
    first = await write_tree(store, Manifest({"a/x": A, "b/y": B}))
    second = await write_tree(store, Manifest({"a/x": A, "b/y": C}))
    assert first != second
    # root and b were rewritten; a is the same object in both.
    assert len(list(store)) == 5


async def test_same_manifest_gives_same_root_in_another_store(
    tmp_path: Path, store: ObjectStore
) -> None:
    other = ObjectStore(tmp_path / "other")
    manifest = Manifest({"docs/x.pdf": A, "log/l.yaml": B})
    assert await write_tree(store, manifest) == await write_tree(
        other, manifest
    )


async def test_empty_manifest_is_one_empty_listing(store: ObjectStore) -> None:
    root = await write_tree(store, Manifest())
    assert await read_tree(store, root) == Manifest()
    assert list(store) == [root.sha256]


async def test_non_ascii_names_round_trip(store: ObjectStore) -> None:
    manifest = Manifest({"docs/Rechnung Müller.pdf": A})
    root = await write_tree(store, manifest)
    assert await read_tree(store, root) == manifest
    docs = Tree.from_yaml((await store.get(root.sha256)).decode())
    listing = await store.get(docs.entries["docs"].digest.sha256)
    assert "Müller" in listing.decode()


async def test_path_that_is_both_file_and_directory_is_rejected(
    store: ObjectStore,
) -> None:
    with pytest.raises(VaultError, match="is also a file"):
        await write_tree(store, Manifest({"a": A, "a/b": B}))


def test_yaml_layout_is_readable_by_hand() -> None:
    tree = Tree(
        {
            "docs": TreeEntry(EntryKind.TREE, B),
            "a.yaml": TreeEntry(EntryKind.FILE, A),
        }
    )
    assert tree.to_yaml() == (
        "entries:\n"
        "  a.yaml:\n"
        "    kind: file\n"
        f"    sha256: {A.sha256}\n"
        "    size: 1\n"
        "  docs:\n"
        "    kind: tree\n"
        f"    sha256: {B.sha256}\n"
        "    size: 1\n"
        "version: 1\n"
    )


def test_entries_are_sorted_by_name() -> None:
    tree = Tree(
        {"z": TreeEntry(EntryKind.FILE, A), "a": TreeEntry(EntryKind.FILE, B)}
    )
    assert list(tree.entries) == ["a", "z"]


@pytest.mark.parametrize("name", ["", "a/b", "/a", ".", "..", "a\nb"])
def test_bad_names_are_rejected(name: str) -> None:
    with pytest.raises(VaultError):
        check_path_component(name)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "a: [",
        "version: 2\nentries: {}\n",
        "version: 1\nentries: [a]\n",
        f"version: 1\nentries:\n  a: {{sha256: {A.sha256}, size: 1}}\n",
        "version: 1\nentries:\n"
        f"  a: {{kind: blob, sha256: {A.sha256}, size: 1}}\n",
        "version: 1\nentries:\n  a: {kind: file, sha256: xyz, size: 1}\n",
        "version: 1\nentries:\n"
        f"  a: {{kind: file, sha256: {A.sha256}, size: -1}}\n",
        f"version: 1\nentries:\n  a/b: {{kind: file, sha256: {A.sha256}, "
        "size: 1}\n",
    ],
)
def test_malformed_yaml_is_rejected(text: str) -> None:
    with pytest.raises(VaultError):
        Tree.from_yaml(text)


async def test_hand_written_objects_are_read(store: ObjectStore) -> None:
    leaf = await store.put_bytes(
        b"version: 1\nentries:\n"
        + f"  x.pdf: {{kind: file, sha256: {A.sha256}, size: 1}}\n".encode()
    )
    root = await store.put_bytes(
        b"version: 1\nentries:\n"
        + f"  docs: {{kind: tree, sha256: {leaf.sha256}, "
        f"size: {leaf.size}}}\n".encode()
    )
    assert await read_tree(store, root) == Manifest({"docs/x.pdf": A})


async def test_missing_object_is_reported(store: ObjectStore) -> None:
    root = await write_tree(store, Manifest({"docs/x.pdf": A}))
    child = Tree.from_yaml((await store.get(root.sha256)).decode())
    store.path(child.entries["docs"].digest.sha256).unlink()
    with pytest.raises(VaultError, match="no object"):
        await read_tree(store, root)


async def test_corrupt_object_is_reported(store: ObjectStore) -> None:
    root = await write_tree(store, Manifest({"docs/x.pdf": A}))
    path = store.path(root.sha256)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    path.write_bytes(
        Tree({"docs": TreeEntry(EntryKind.FILE, B)}).to_yaml().encode()
    )
    with pytest.raises(CorruptObjectError):
        await read_tree(store, root)


async def test_size_mismatch_is_reported(store: ObjectStore) -> None:
    root = await write_tree(store, Manifest({"x": A}))
    with pytest.raises(VaultError, match="bytes"):
        await read_tree(store, Digest(root.sha256, root.size + 1))


async def test_object_that_is_not_text_is_reported(store: ObjectStore) -> None:
    digest = await store.put_bytes(b"\xff\xfe")
    with pytest.raises(VaultError, match="UTF-8"):
        await read_tree(store, digest)


async def test_object_that_is_not_yaml_is_reported(store: ObjectStore) -> None:
    digest = await store.put_bytes(b"a: [")
    with pytest.raises(VaultError, match="not YAML"):
        await read_tree(store, digest)
