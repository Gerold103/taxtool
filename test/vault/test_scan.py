import os
from pathlib import Path

import pytest

from vault.errors import VaultError
from vault.hashing import Digest, digest_bytes
from vault.manifest import Manifest
from vault.scan import Changes, compare_manifests, scan_files

A = digest_bytes(b"a")
B = digest_bytes(b"b")


def populate(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


async def test_scan_hashes_every_regular_file(tmp_path: Path) -> None:
    files = {
        "config.yaml": b"version: 1\n",
        "docs/a.pdf": os.urandom(100),
        "periods/2025/log/log_00001.yaml": b"events:\n",
    }
    populate(tmp_path, files)
    (tmp_path / "empty_dir").mkdir()
    manifest = await scan_files(tmp_path)
    assert manifest == Manifest(
        {rel: digest_bytes(data) for rel, data in files.items()}
    )


async def test_scan_excludes_files_and_whole_directories(
    tmp_path: Path,
) -> None:
    populate(
        tmp_path,
        {
            ".vault/objects/ab/cd": b"blob",
            "README.md": b"human",
            "README.md.bak": b"not the same entry",
            "docs/a.pdf": b"doc",
            "periods/2025/log/l.yaml": b"leaf, has its own manifest",
            "periods/index.yaml": b"root-level, stays",
        },
    )
    exclude = {".vault", "README.md", "periods/2025"}
    manifest = await scan_files(tmp_path, exclude)
    assert list(manifest.files) == [
        "README.md.bak",
        "docs/a.pdf",
        "periods/index.yaml",
    ]


async def test_non_ascii_names_survive_scan_yaml_and_cache(
    tmp_path: Path,
) -> None:
    files = {
        "docs/Rechnung Müller GmbH.pdf": b"umlaut",
        "docs/Счёт № 7.pdf": b"cyrillic",
        "docs/Ελλάδα/τιμολόγιο.pdf": b"greek",
    }
    populate(tmp_path, files)
    cache = tmp_path / "state" / "cache"
    manifest = await scan_files(tmp_path, exclude={"state"}, cache=cache)
    assert set(manifest.files) == set(files)
    text = manifest.to_yaml()
    assert "Rechnung Müller GmbH.pdf" in text
    assert "Счёт № 7.pdf" in text
    assert Manifest.from_yaml(text) == manifest
    assert (
        await scan_files(tmp_path, exclude={"state"}, cache=cache) == manifest
    )
    assert not await compare_manifests(tmp_path, manifest, manifest)


async def test_scan_rejects_unclean_exclude(tmp_path: Path) -> None:
    with pytest.raises(VaultError, match="clean relative path"):
        await scan_files(tmp_path, {"../outside"})


async def test_scan_of_empty_directory(tmp_path: Path) -> None:
    assert await scan_files(tmp_path) == Manifest()


async def test_scan_rejects_symlink(tmp_path: Path) -> None:
    populate(tmp_path, {"real.txt": b"x"})
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    with pytest.raises(VaultError, match="symlinks are not allowed"):
        await scan_files(tmp_path)


async def test_scan_rejects_special_file(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(VaultError, match="not a regular file"):
        await scan_files(tmp_path)


async def test_scan_of_missing_directory_fails(tmp_path: Path) -> None:
    with pytest.raises(VaultError, match="not a directory"):
        await scan_files(tmp_path / "nowhere")


async def test_changes_reports_all_four_kinds(tmp_path: Path) -> None:
    before = {
        "log/log_00001.yaml": b"events:\n- a\n",
        "log/log_00002.yaml": b"events:\n- b\n",
        "master.yaml": b"v1\n",
        "notes.txt": b"same",
        "keep.txt": b"keep",
    }
    populate(tmp_path, before)
    old = await scan_files(tmp_path)
    populate(
        tmp_path,
        {
            "log/log_00001.yaml": before["log/log_00001.yaml"] + b"- c\n",
            "log/log_00002.yaml": b"events:\n- B\n",
            "master.yaml": b"v1\nmore\n",
            "new.txt": b"fresh",
        },
    )
    (tmp_path / "notes.txt").unlink()
    new = await scan_files(tmp_path)
    result = await compare_manifests(tmp_path, old, new)

    def pair(rel: str) -> tuple[Digest, Digest]:
        return (old.files[rel], new.files[rel])

    assert result == Changes(
        added={"new.txt": new.files["new.txt"]},
        appended={
            "log/log_00001.yaml": pair("log/log_00001.yaml"),
            "master.yaml": pair("master.yaml"),
        },
        changed={"log/log_00002.yaml": pair("log/log_00002.yaml")},
        deleted={"notes.txt": old.files["notes.txt"]},
    )
    assert result
    assert result.paths() == [
        "log/log_00001.yaml",
        "log/log_00002.yaml",
        "master.yaml",
        "new.txt",
        "notes.txt",
    ]


async def test_truncated_file_is_a_rewrite_not_an_append(
    tmp_path: Path,
) -> None:
    populate(tmp_path, {"log/l.yaml": b"events:\n- a\n- b\n"})
    old = await scan_files(tmp_path)
    populate(tmp_path, {"log/l.yaml": b"events:\n- a\n"})
    new = await scan_files(tmp_path)
    result = await compare_manifests(tmp_path, old, new)
    assert list(result.changed) == ["log/l.yaml"]
    assert not result.appended


async def test_grown_file_with_edited_prefix_is_a_rewrite(
    tmp_path: Path,
) -> None:
    populate(tmp_path, {"log/l.yaml": b"events:\n- a\n"})
    old = await scan_files(tmp_path)
    populate(tmp_path, {"log/l.yaml": b"events:\n- A\n- b\n"})
    new = await scan_files(tmp_path)
    result = await compare_manifests(tmp_path, old, new)
    assert list(result.changed) == ["log/l.yaml"]
    assert not result.appended


async def test_no_changes_is_falsy(tmp_path: Path) -> None:
    populate(tmp_path, {"a": b"a"})
    manifest = await scan_files(tmp_path)
    result = await compare_manifests(tmp_path, manifest, manifest)
    assert not result
    assert result.paths() == []


async def test_changes_compare_size_as_well_as_hash(tmp_path: Path) -> None:
    populate(tmp_path, {"a": b"a"})
    new = await scan_files(tmp_path)
    old = Manifest({"a": Digest(A.sha256, 5)})
    result = await compare_manifests(tmp_path, old, new)
    assert list(result.changed) == ["a"]
