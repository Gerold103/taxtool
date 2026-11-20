import pytest

from vault.errors import VaultError
from vault.hashing import Digest, digest_bytes
from vault.manifest import Changes, Manifest, check_relpath, diff

A = digest_bytes(b"a")
B = digest_bytes(b"b")
C = digest_bytes(b"c")


def test_files_are_sorted_by_path() -> None:
    manifest = Manifest({"z.txt": A, "docs/b.pdf": B, "a.yaml": C})
    assert list(manifest.files) == ["a.yaml", "docs/b.pdf", "z.txt"]


def test_yaml_round_trip_is_identical_and_deterministic() -> None:
    manifest = Manifest({"log/log_00001.yaml": A, "docs/x.pdf": B})
    text = manifest.to_yaml()
    assert Manifest.from_yaml(text) == manifest
    assert Manifest({"docs/x.pdf": B, "log/log_00001.yaml": A}).to_yaml() == (
        text
    )


def test_yaml_layout_is_readable_by_hand() -> None:
    text = Manifest({"docs/x.pdf": A}).to_yaml()
    assert text == (
        "files:\n"
        "  docs/x.pdf:\n"
        f"    sha256: {A.sha256}\n"
        "    size: 1\n"
        "version: 1\n"
    )


def test_yaml_lines_stay_within_80_columns() -> None:
    long_name = "periods/2026/H2/docs/invoices/" + "x" * 40 + ".pdf"
    text = Manifest({long_name: A}).to_yaml()
    assert all(len(line) <= 80 for line in text.splitlines())


def test_empty_manifest_round_trips() -> None:
    assert Manifest.from_yaml(Manifest().to_yaml()) == Manifest()
    assert Manifest.from_yaml("version: 1\n") == Manifest()


@pytest.mark.parametrize(
    "text",
    [
        "",
        "version: 2\nfiles: {}\n",
        "version: 1\nfiles: [a]\n",
        "version: 1\nfiles:\n  a: {sha256: xyz, size: 1}\n",
        f"version: 1\nfiles:\n  a: {{sha256: {A.sha256}}}\n",
        f"version: 1\nfiles:\n  a: {{sha256: {A.sha256}, size: -1}}\n",
    ],
)
def test_malformed_yaml_is_rejected(text: str) -> None:
    with pytest.raises(VaultError):
        Manifest.from_yaml(text)


@pytest.mark.parametrize(
    "bad", ["", "/abs", "a/../b", "./a", "a/", "a//b", "a/./b"]
)
def test_unclean_paths_are_rejected(bad: str) -> None:
    with pytest.raises(VaultError, match="clean relative path"):
        check_relpath(bad)
    with pytest.raises(VaultError):
        Manifest({bad: A})


def test_diff_reports_added_changed_deleted() -> None:
    old = Manifest({"keep": A, "change": A, "gone": B})
    new = Manifest({"keep": A, "change": B, "new": C})
    changes = diff(old, new)
    assert changes == Changes(
        added={"new": C}, changed={"change": (A, B)}, deleted={"gone": B}
    )
    assert list(changes.paths()) == ["change", "gone", "new"]
    assert changes


def test_diff_of_equal_manifests_is_empty() -> None:
    manifest = Manifest({"a": A})
    changes = diff(manifest, manifest)
    assert not changes
    assert list(changes.paths()) == []


def test_digest_is_compared_by_size_too() -> None:
    old = Manifest({"a": Digest(A.sha256, 1)})
    new = Manifest({"a": Digest(A.sha256, 2)})
    assert diff(old, new).changed == {"a": (old.files["a"], new.files["a"])}
