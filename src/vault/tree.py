"""Tree objects: a Manifest stored as one object per directory.

A tree object is the YAML listing of one directory: each entry is a name
with the kind of thing it names, a file or another tree, and the Digest of
that thing's bytes. For a file that is the file's own content; for a tree
it is the child listing's YAML. The listing is written to the object store
like any blob, so its hash is its identity and the root tree's Digest
stands for the whole Manifest.

This is git's model. A seal records only the root, which still reaches
every file, so every seal describes the complete data root and verifies on
its own. Between two seals only the directories on the path to a changed
file get a new listing; every unchanged subtree keeps its hash and is the
same object in the store, shared by both seals. Entries are sorted and the
YAML is deterministic, so the same directory contents always produce the
same object.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import yaml

from vault.errors import CorruptObjectError, VaultError
from vault.hashing import Digest, digest_bytes
from vault.manifest import Manifest, check_relpath, parse_digest
from vault.objects import ObjectStore

VERSION = 1


class EntryKind(StrEnum):
    FILE = "file"
    TREE = "tree"


@dataclass(frozen=True)
class TreeEntry:
    """What one name in a directory points at."""

    kind: EntryKind
    digest: Digest


def check_path_component(name: str) -> str:
    """One path component: a clean relative path without a separator."""
    check_relpath(name)
    if "/" in name:
        raise VaultError(f"not a single path component: {name!r}")
    return name


@dataclass(frozen=True)
class Tree:
    """Name -> TreeEntry for the direct children of one directory."""

    entries: Mapping[str, TreeEntry] = field(default_factory=dict)

    def __post_init__(self) -> None:
        ordered = {
            check_path_component(n): self.entries[n]
            for n in sorted(self.entries)
        }
        object.__setattr__(self, "entries", ordered)

    def to_yaml(self) -> str:
        data = {
            "version": VERSION,
            "entries": {
                name: {
                    "kind": e.kind.value,
                    "sha256": e.digest.sha256,
                    "size": e.digest.size,
                }
                for name, e in self.entries.items()
            },
        }
        text: str = yaml.safe_dump(
            data,
            sort_keys=True,
            default_flow_style=False,
            width=80,
            allow_unicode=True,
        )
        return text

    @classmethod
    def from_yaml(cls, text: str) -> "Tree":
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise VaultError("not a tree object: not YAML") from error
        if not isinstance(data, dict) or data.get("version") != VERSION:
            raise VaultError("not a tree object: missing or unknown version")
        entries = data.get("entries")
        if entries is None:
            entries = {}
        if not isinstance(entries, dict):
            raise VaultError("not a tree object: entries is not a mapping")
        return cls({str(n): _entry_from_yaml(n, e) for n, e in entries.items()})


def _entry_from_yaml(name: Any, entry: Any) -> TreeEntry:
    digest = parse_digest(name, entry)
    try:
        kind = EntryKind(entry.get("kind"))
    except ValueError:
        raise VaultError(
            f"tree entry for {name!r} has an unknown kind"
        ) from None
    return TreeEntry(kind, digest)


type Listing = dict[str, Digest | Listing]


def _nest_paths(manifest: Manifest) -> Listing:
    """Group the flat paths of a Manifest by directory."""
    root: Listing = {}
    for path, digest in manifest.files.items():
        *parents, name = path.split("/")
        listing = root
        for parent in parents:
            child = listing.setdefault(parent, {})
            if not isinstance(child, dict):
                raise VaultError(f"{path}: {parent!r} is also a file")
            listing = child
        listing[name] = digest
    return root


async def _write_listing(store: ObjectStore, listing: Listing) -> Digest:
    entries: dict[str, TreeEntry] = {}
    for name, item in listing.items():
        if isinstance(item, dict):
            entries[name] = TreeEntry(
                EntryKind.TREE, await _write_listing(store, item)
            )
        else:
            entries[name] = TreeEntry(EntryKind.FILE, item)
    return await store.put_bytes(Tree(entries).to_yaml().encode())


async def write_tree(store: ObjectStore, manifest: Manifest) -> Digest:
    """Store the Manifest as tree objects; return the root tree's Digest."""
    return await _write_listing(store, _nest_paths(manifest))


async def _read_listing(
    store: ObjectStore, digest: Digest, prefix: str, files: dict[str, Digest]
) -> None:
    data = await store.get(digest.sha256)
    actual = digest_bytes(data)
    if actual.sha256 != digest.sha256:
        raise CorruptObjectError(digest.sha256, actual.sha256)
    if actual.size != digest.size:
        raise VaultError(
            f"tree object {digest.sha256} has {actual.size} bytes, "
            f"its parent lists {digest.size}"
        )
    try:
        text = data.decode()
    except UnicodeDecodeError as error:
        raise VaultError(f"tree object {digest.sha256} is not UTF-8") from error
    tree = Tree.from_yaml(text)
    for name, entry in tree.entries.items():
        path = prefix + name
        if entry.kind is EntryKind.TREE:
            await _read_listing(store, entry.digest, path + "/", files)
        else:
            files[path] = entry.digest


async def read_tree(store: ObjectStore, root: Digest) -> Manifest:
    """Rebuild the Manifest below a root tree, checking every object."""
    files: dict[str, Digest] = {}
    await _read_listing(store, root, "", files)
    return Manifest(files)
