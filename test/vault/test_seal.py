import os
import stat
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

from support.local_calendar import LocalCalendar
from support.local_explorer import LocalExplorer
from vault import tree
from vault.authorities import Complete, Pending
from vault.authorities.local_hmac import TOKEN_FILE, LocalHmacAuthority
from vault.authorities.opentimestamps import (
    COMPLETE_FILE,
    OpenTimestampsAuthority,
)
from vault.errors import VaultError
from vault.events import (
    ABANDONED_FILE,
    FileAppended,
    ProofCompleted,
    SealAdded,
    classify,
)
from vault.hashing import digest_bytes
from vault.objects import ObjectStore
from vault.scan import changes, scan
from vault.seal import (
    CACHE_FILE,
    OBJECTS_DIR,
    Abandoned,
    Failed,
    SealRecord,
    abandon,
    complete,
    create,
    ids,
    latest,
    load,
    proof_dir,
)

HOME = PurePosixPath(".app/.vault")
NOW = datetime(2026, 11, 27, 10, 0, tzinfo=UTC)
LATER = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)
HEIGHT = 900_000
MINED = datetime(2026, 11, 27, 16, 0, tzinfo=UTC)
A = digest_bytes(b"a")
PREVIOUS = digest_bytes(b"previous").sha256


@pytest.fixture
def root(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    (data / "docs" / "2026").mkdir(parents=True)
    (data / "log").mkdir()
    (data / "config.yaml").write_text("name: example\n")
    (data / "docs" / "2026" / "inv.pdf").write_bytes(b"%PDF-1.7\n")
    (data / "log" / "l.yaml").write_text("- one\n")
    return data


@pytest.fixture
def home(root: Path) -> Path:
    path = root / HOME
    path.mkdir(parents=True)
    return path


@pytest.fixture
def local_authority(home: Path) -> LocalHmacAuthority:
    key_file = home / "authorities" / "local" / "key"
    key_file.parent.mkdir(parents=True)
    key_file.write_text(os.urandom(32).hex() + "\n")
    return LocalHmacAuthority("local", key_file)


@pytest.fixture
def broken_authority(home: Path) -> LocalHmacAuthority:
    """An authority whose key file does not exist, so every stamp fails."""
    return LocalHmacAuthority("broken", home / "authorities" / "broken" / "key")


@pytest.fixture
async def calendar() -> AsyncIterator[LocalCalendar]:
    server = LocalCalendar()
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
async def explorer() -> AsyncIterator[LocalExplorer]:
    server = LocalExplorer()
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
def ots_authority(
    calendar: LocalCalendar, explorer: LocalExplorer
) -> OpenTimestampsAuthority:
    return OpenTimestampsAuthority("ots", calendar.url, explorer.url)


def object_store(home: Path) -> ObjectStore:
    return ObjectStore(home / OBJECTS_DIR)


def is_read_only(path: Path) -> bool:
    return not path.stat().st_mode & stat.S_IWUSR


async def test_first_seal_records_tree_time_and_authorities(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    status = await create(root, home, [local_authority], NOW)
    seal = status.seal
    assert seal.id == 1
    assert seal.dir == home / "seals" / "000001"
    assert seal.record.time == NOW
    assert seal.record.previous is None
    assert seal.record.authorities == ("local",)
    data = (seal.dir / "seal.yaml").read_bytes()
    assert SealRecord.from_yaml(data.decode()) == seal.record
    assert digest_bytes(data).sha256 == seal.root
    assert is_read_only(seal.dir / "seal.yaml")
    assert status.proofs == {"local": Complete(NOW)}
    assert (proof_dir(seal, "local") / TOKEN_FILE).is_file()


async def test_tree_covers_data_and_home_but_not_store_and_cache(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    status = await create(root, home, [local_authority], NOW)
    manifest = await tree.read(object_store(home), status.seal.record.tree)
    assert set(manifest.files) == {
        "config.yaml",
        "docs/2026/inv.pdf",
        "log/l.yaml",
        ".app/.vault/authorities/local/key",
    }
    assert (home / CACHE_FILE).is_file()
    assert len(list(object_store(home))) > 0


async def test_second_seal_chains_to_and_covers_the_first(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    first = await create(root, home, [local_authority], NOW)
    with (root / "log" / "l.yaml").open("a") as log:
        log.write("- two\n")
    second = await create(root, home, [local_authority], LATER)
    assert second.seal.id == 2
    assert second.seal.record.previous == first.seal.root
    manifest = await tree.read(object_store(home), second.seal.record.tree)
    record = ".app/.vault/seals/000001/seal.yaml"
    assert manifest.files[record].sha256 == first.seal.root
    assert ".app/.vault/seals/000001/proof/local/token.yaml" in manifest.files
    assert ".app/.vault/seals/000002/seal.yaml" not in manifest.files


async def test_exclude_leaves_paths_out_of_the_tree(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    status = await create(root, home, [local_authority], NOW, exclude=["docs"])
    manifest = await tree.read(object_store(home), status.seal.record.tree)
    assert "config.yaml" in manifest.files
    assert not any(p.startswith("docs/") for p in manifest.files)


async def test_ids_latest_and_load(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    assert ids(home) == []
    assert await latest(home) is None
    await create(root, home, [local_authority], NOW)
    await create(root, home, [local_authority], LATER)
    assert ids(home) == [1, 2]
    newest = await latest(home)
    assert newest is not None and newest.id == 2
    assert (await load(home, 1)).record.time == NOW


def test_ids_ignores_other_entries(home: Path) -> None:
    seals = home / "seals"
    for name in ["000001", "1", "abc", "0000012"]:
        (seals / name).mkdir(parents=True)
    (seals / "000003").write_text("a file, not a seal\n")
    assert ids(home) == [1]


async def test_create_needs_an_authority(root: Path, home: Path) -> None:
    with pytest.raises(VaultError, match="at least one authority"):
        await create(root, home, [], NOW)


async def test_duplicate_authority_names_are_rejected(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    with pytest.raises(VaultError, match="two authorities"):
        await create(root, home, [local_authority, local_authority], NOW)
    assert ids(home) == []


async def test_authority_name_must_be_one_path_component(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    with pytest.raises(VaultError, match="single path component"):
        await create(
            root,
            home,
            [LocalHmacAuthority("a/b", local_authority.key_file)],
            NOW,
        )


async def test_home_must_be_inside_the_root(
    tmp_path: Path, root: Path, local_authority: LocalHmacAuthority
) -> None:
    with pytest.raises(VaultError, match="not inside"):
        await create(root, tmp_path / "elsewhere", [local_authority], NOW)
    with pytest.raises(VaultError):
        await create(root, root, [local_authority], NOW)


async def test_naive_time_is_rejected(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    with pytest.raises(VaultError, match="timezone"):
        await create(root, home, [local_authority], datetime(2026, 11, 27))


async def test_no_accepting_authority_leaves_no_seal(
    root: Path, home: Path, broken_authority: LocalHmacAuthority
) -> None:
    with pytest.raises(VaultError, match="no authority accepted") as info:
        await create(root, home, [broken_authority], NOW)
    assert "broken: authority broken: cannot read hex key" in str(info.value)
    assert ids(home) == []
    assert not (home / "seals" / "000001").exists()


async def test_one_failing_authority_is_reported_and_kept(
    root: Path,
    home: Path,
    local_authority: LocalHmacAuthority,
    broken_authority: LocalHmacAuthority,
) -> None:
    status = await create(root, home, [local_authority, broken_authority], NOW)
    assert status.seal.record.authorities == ("local", "broken")
    assert status.proofs["local"] == Complete(NOW)
    failed = status.proofs["broken"]
    assert isinstance(failed, Failed)
    assert "cannot read hex key" in failed.why
    assert proof_dir(status.seal, "broken").is_dir()


def test_record_yaml_is_readable_by_hand() -> None:
    record = SealRecord(3, NOW, A, PREVIOUS, ("local", "ots"))
    assert record.to_yaml() == (
        "version: 1\n"
        "id: 3\n"
        "time: '2026-11-27T10:00:00+00:00'\n"
        "tree:\n"
        f"  sha256: {A.sha256}\n"
        "  size: 1\n"
        f"previous: {PREVIOUS}\n"
        "authorities:\n"
        "- local\n"
        "- ots\n"
    )


def test_record_round_trips_with_and_without_previous() -> None:
    for previous in [PREVIOUS, None]:
        record = SealRecord(1, NOW, A, previous, ("local",))
        assert SealRecord.from_yaml(record.to_yaml()) == record


def test_unquoted_time_is_accepted() -> None:
    record = SealRecord(1, NOW, A, None, ("local",))
    text = record.to_yaml().replace("'", "")
    assert isinstance(yaml.safe_load(text)["time"], datetime)
    assert SealRecord.from_yaml(text) == record


def record_text(**overrides: Any) -> str:
    data: dict[str, Any] = {
        "version": 1,
        "id": 1,
        "time": NOW.isoformat(),
        "tree": {"sha256": A.sha256, "size": 1},
        "previous": None,
        "authorities": ["local"],
    }
    data.update(overrides)
    return yaml.safe_dump({k: v for k, v in data.items() if v != "absent"})


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "not a seal record"),
        ("a: [", "not YAML"),
        (record_text(version=2), "unknown version"),
        (record_text(id=0), "positive integer"),
        (record_text(id="1"), "positive integer"),
        (record_text(time="absent"), "time is missing"),
        (record_text(time="yesterday"), "unreadable time"),
        (record_text(time="2026-11-27T10:00:00"), "timezone"),
        (record_text(tree="absent"), "digest entry"),
        (record_text(tree={"sha256": A.sha256, "size": -1}), "digest entry"),
        (record_text(previous="xyz"), "previous"),
        (record_text(authorities=[]), "list of names"),
        (record_text(authorities="local"), "list of names"),
        (record_text(authorities=[1]), "list of names"),
    ],
)
def test_malformed_records_are_rejected(text: str, message: str) -> None:
    with pytest.raises(VaultError, match=message):
        SealRecord.from_yaml(text)


async def test_load_reports_a_missing_record(home: Path) -> None:
    with pytest.raises(VaultError, match="no record"):
        await load(home, 1)


async def test_load_detects_a_moved_seal(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    status = await create(root, home, [local_authority], NOW)
    status.seal.dir.rename(home / "seals" / "000002")
    with pytest.raises(VaultError, match="says it is seal 1"):
        await load(home, 2)


async def test_load_rejects_a_binary_record(home: Path) -> None:
    directory = home / "seals" / "000001"
    directory.mkdir(parents=True)
    (directory / "seal.yaml").write_bytes(b"\xff\xfe")
    with pytest.raises(VaultError, match="not UTF-8"):
        await load(home, 1)


async def test_abandon_writes_a_marker_that_complete_reports(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    status = await create(root, home, [local_authority], NOW)
    marker = await abandon(home, 1, "local", LATER, "key lost")
    assert marker == Abandoned(LATER, "key lost")
    path = proof_dir(status.seal, "local") / ABANDONED_FILE
    assert yaml.safe_load(path.read_text()) == {
        "time": LATER.isoformat(),
        "why": "key lost",
    }
    assert is_read_only(path)
    [report] = await complete(home, [local_authority])
    assert report.proofs == {"local": marker}


async def test_abandon_refuses_bad_requests(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    await create(root, home, [local_authority], NOW)
    with pytest.raises(VaultError, match="needs a reason"):
        await abandon(home, 1, "local", LATER, "  ")
    with pytest.raises(VaultError, match="did not ask"):
        await abandon(home, 1, "ots", LATER, "dead")
    with pytest.raises(VaultError, match="no record"):
        await abandon(home, 2, "local", LATER, "dead")
    await abandon(home, 1, "local", LATER, "dead")
    with pytest.raises(VaultError, match="already exists"):
        await abandon(home, 1, "local", LATER, "dead again")


async def test_complete_reports_an_unconfigured_authority(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    await create(root, home, [local_authority], NOW)
    [report] = await complete(home, [])
    assert report.proofs == {
        "local": Failed("authority 'local' is not configured")
    }


async def test_complete_one_seal_or_all(
    root: Path, home: Path, local_authority: LocalHmacAuthority
) -> None:
    await create(root, home, [local_authority], NOW)
    await create(root, home, [local_authority], LATER)
    assert [s.seal.id for s in await complete(home, [local_authority])] == [
        1,
        2,
    ]
    [only] = await complete(home, [local_authority], 2)
    assert only.seal.id == 2
    assert only.proofs == {"local": Complete(LATER)}
    with pytest.raises(VaultError, match="no record"):
        await complete(home, [local_authority], 5)


async def test_pending_proof_completes_once_mined(
    root: Path,
    home: Path,
    local_authority: LocalHmacAuthority,
    ots_authority: OpenTimestampsAuthority,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    status = await create(root, home, [local_authority, ots_authority], NOW)
    assert status.proofs["local"] == Complete(NOW)
    assert isinstance(status.proofs["ots"], Pending)
    [report] = await complete(home, [local_authority, ots_authority])
    assert isinstance(report.proofs["ots"], Pending)
    assert not (proof_dir(status.seal, "ots") / COMPLETE_FILE).exists()

    explorer.headers[HEIGHT] = calendar.mine(HEIGHT, MINED)
    [report] = await complete(home, [local_authority, ots_authority])
    assert report.proofs == {"local": Complete(NOW), "ots": Complete(MINED)}
    assert (proof_dir(status.seal, "ots") / COMPLETE_FILE).is_file()


async def test_a_seals_own_files_are_changes_against_its_own_tree(
    root: Path,
    home: Path,
    local_authority: LocalHmacAuthority,
    ots_authority: OpenTimestampsAuthority,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    """The record and proofs are written after the tree, so they are new
    to it; `status` leaves the newest seal's directory out for that
    reason, and the next seal's tree is the first to cover it."""
    status = await create(root, home, [local_authority, ots_authority], NOW)
    explorer.headers[HEIGHT] = calendar.mine(HEIGHT, MINED)
    await complete(home, [local_authority, ots_authority])
    with (root / "log" / "l.yaml").open("a") as log:
        log.write("- two\n")

    sealed = await tree.read(object_store(home), status.seal.record.tree)
    exclude = [str(HOME / OBJECTS_DIR), str(HOME / CACHE_FILE)]
    now = await scan(root, exclude)
    events = classify(await changes(root, sealed, now), HOME)
    assert events == [
        ProofCompleted(1, "local"),
        ProofCompleted(1, "ots"),
        SealAdded(1),
        FileAppended("log/l.yaml"),
    ]
