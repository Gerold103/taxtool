import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from support.local_calendar import PENDING_TEXT, LocalCalendar
from support.local_explorer import LocalExplorer
from vault.authorities import Authority, Complete, Pending
from vault.authorities.opentimestamps import (
    COMPLETE_FILE,
    HEADER_FILE,
    PENDING_FILE,
    PENDING_WHY,
    STAMP_FILE,
    OpenTimestampsAuthority,
)
from vault.errors import VaultError
from vault.hashing import digest_bytes
from vault.ots.attestation import Bitcoin
from vault.ots.file import parse_file, serialize_file
from vault.ots.ops import TAG_APPEND, TAG_PREPEND, Op

DATA = Path(__file__).resolve().parents[1] / "support" / "data" / "ots"
ROOT = digest_bytes(b"root manifest").sha256
OTHER = digest_bytes(b"other").sha256
SEALED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
HEIGHT = 900_000
MINED = datetime(2026, 1, 2, 9, 0, 0, tzinfo=UTC)


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
def authority(
    calendar: LocalCalendar, explorer: LocalExplorer
) -> OpenTimestampsAuthority:
    return OpenTimestampsAuthority("ots", calendar.url, explorer.url)


@pytest.fixture
def proof_dir(tmp_path: Path) -> Path:
    path = tmp_path / "vault" / "seals" / "000001" / "proof" / "ots"
    path.mkdir(parents=True)
    return path


def files(proof_dir: Path) -> set[str]:
    return {p.name for p in proof_dir.iterdir()}


async def stamp_and_mine(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    await authority.stamp(ROOT, SEALED, proof_dir)
    explorer.headers[HEIGHT] = calendar.mine(HEIGHT, MINED)


def test_satisfies_protocol(authority: OpenTimestampsAuthority) -> None:
    held: Authority = authority
    assert held.name == "ots"


async def test_stamp_writes_the_pending_proof_and_the_record(
    authority: OpenTimestampsAuthority, proof_dir: Path, calendar: LocalCalendar
) -> None:
    stamped = await authority.stamp(ROOT, SEALED, proof_dir)
    assert stamped == Pending(SEALED, PENDING_WHY)
    assert files(proof_dir) == {PENDING_FILE, STAMP_FILE}
    proof = parse_file((proof_dir / PENDING_FILE).read_bytes())
    assert proof.msg.hex() == ROOT
    record = yaml.safe_load((proof_dir / STAMP_FILE).read_text("utf-8"))
    assert record == {
        "type": "opentimestamps",
        "authority": "ots",
        "calendar": calendar.url,
        "time": "2026-01-02T03:04:05+00:00",
    }


async def test_complete_before_the_block_stays_pending_with_the_reason(
    authority: OpenTimestampsAuthority, proof_dir: Path, calendar: LocalCalendar
) -> None:
    await authority.stamp(ROOT, SEALED, proof_dir)
    completed = await authority.complete(ROOT, proof_dir)
    assert completed == Pending(SEALED, f"{calendar.url}: {PENDING_TEXT}")
    assert files(proof_dir) == {PENDING_FILE, STAMP_FILE}


async def test_verify_while_pending_reports_pending_offline(
    authority: OpenTimestampsAuthority, proof_dir: Path, calendar: LocalCalendar
) -> None:
    await authority.stamp(ROOT, SEALED, proof_dir)
    await calendar.stop()
    assert await authority.verify(ROOT, proof_dir) == Pending(
        SEALED, PENDING_WHY
    )


async def test_complete_after_the_block_adds_proof_and_header(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    await stamp_and_mine(authority, proof_dir, calendar, explorer)
    pending_before = (proof_dir / PENDING_FILE).read_bytes()
    completed = await authority.complete(ROOT, proof_dir)
    assert completed == Complete(MINED)
    assert files(proof_dir) == {
        PENDING_FILE,
        STAMP_FILE,
        COMPLETE_FILE,
        HEADER_FILE,
    }
    assert (proof_dir / PENDING_FILE).read_bytes() == pending_before
    header = explorer.headers[HEIGHT]
    assert (proof_dir / HEADER_FILE).read_bytes() == header.raw
    proof = parse_file((proof_dir / COMPLETE_FILE).read_bytes())
    (node, _), *_ = [
        (n, a) for n, a in proof.all_attestations() if a == Bitcoin(HEIGHT)
    ]
    assert node.msg == header.merkle_root


async def test_complete_proof_verifies_offline(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    await stamp_and_mine(authority, proof_dir, calendar, explorer)
    await authority.complete(ROOT, proof_dir)
    await calendar.stop()
    await explorer.stop()
    assert await authority.verify(ROOT, proof_dir) == Complete(MINED)
    assert await authority.complete(ROOT, proof_dir) == Complete(MINED)


async def test_real_proof_verifies_against_the_real_header(
    authority: OpenTimestampsAuthority, proof_dir: Path
) -> None:
    (proof_dir / COMPLETE_FILE).write_bytes(
        (DATA / "hello-world.txt.ots").read_bytes()
    )
    (proof_dir / HEADER_FILE).write_bytes(
        (DATA / "block-358391.bin").read_bytes()
    )
    root = hashlib.sha256((DATA / "hello-world.txt").read_bytes()).hexdigest()
    assert await authority.verify(root, proof_dir) == Complete(
        datetime(2015, 5, 28, 15, 41, 18, tzinfo=UTC)
    )


async def test_header_with_another_merkle_root_is_refused_and_not_written(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    calendar.misbehave = "bad-header"
    await stamp_and_mine(authority, proof_dir, calendar, explorer)
    with pytest.raises(VaultError, match="is not the merkle root of the saved"):
        await authority.complete(ROOT, proof_dir)
    assert files(proof_dir) == {PENDING_FILE, STAMP_FILE}


async def test_altered_sibling_hash_fails_verification(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    await stamp_and_mine(authority, proof_dir, calendar, explorer)
    await authority.complete(ROOT, proof_dir)
    proof = parse_file((proof_dir / COMPLETE_FILE).read_bytes())
    node, op = next(
        (node, op)
        for node in proof.walk()
        for op in node.ops
        if op.tag in (TAG_APPEND, TAG_PREPEND)
    )
    altered = Op(op.tag, bytes([op.arg[0] ^ 1]) + op.arg[1:])
    node.ops[altered] = node.ops.pop(op)
    (proof_dir / COMPLETE_FILE).write_bytes(serialize_file(proof))
    with pytest.raises(VaultError, match="is not the merkle root of the saved"):
        await authority.verify(ROOT, proof_dir)


async def test_altered_header_fails_proof_of_work(
    authority: OpenTimestampsAuthority, proof_dir: Path
) -> None:
    # The real block, at real difficulty: the locally mined ones accept
    # half of all hashes, so a flipped bit there passes half the time.
    (proof_dir / COMPLETE_FILE).write_bytes(
        (DATA / "hello-world.txt.ots").read_bytes()
    )
    raw = bytearray((DATA / "block-358391.bin").read_bytes())
    raw[-1] ^= 1
    (proof_dir / HEADER_FILE).write_bytes(raw)
    root = hashlib.sha256((DATA / "hello-world.txt").read_bytes()).hexdigest()
    with pytest.raises(VaultError, match="fails its own proof of work"):
        await authority.verify(root, proof_dir)


async def test_second_bitcoin_attestation_is_refused(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    await stamp_and_mine(authority, proof_dir, calendar, explorer)
    await authority.complete(ROOT, proof_dir)
    proof = parse_file((proof_dir / COMPLETE_FILE).read_bytes())
    proof.attestations.add(Bitcoin(1))
    (proof_dir / COMPLETE_FILE).write_bytes(serialize_file(proof))
    with pytest.raises(VaultError, match="has 2 Bitcoin attestations"):
        await authority.verify(ROOT, proof_dir)


async def test_proof_for_another_hash_is_refused(
    authority: OpenTimestampsAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, SEALED, proof_dir)
    with pytest.raises(VaultError, match=f"is for hash {ROOT}, not {OTHER}"):
        await authority.verify(OTHER, proof_dir)


async def test_missing_proof_is_refused(
    authority: OpenTimestampsAuthority, proof_dir: Path
) -> None:
    with pytest.raises(VaultError, match="authority ots: no proof at"):
        await authority.verify(ROOT, proof_dir)


async def test_missing_header_is_refused(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
    explorer: LocalExplorer,
) -> None:
    await stamp_and_mine(authority, proof_dir, calendar, explorer)
    await authority.complete(ROOT, proof_dir)
    (proof_dir / HEADER_FILE).unlink()
    with pytest.raises(VaultError, match=f"{HEADER_FILE} is missing"):
        await authority.verify(ROOT, proof_dir)


async def test_malformed_record_is_refused(
    authority: OpenTimestampsAuthority, proof_dir: Path
) -> None:
    await authority.stamp(ROOT, SEALED, proof_dir)
    (proof_dir / STAMP_FILE).write_text("type: other\n", encoding="utf-8")
    with pytest.raises(VaultError, match="is missing or malformed"):
        await authority.verify(ROOT, proof_dir)


async def test_pending_proof_without_a_calendar_is_refused(
    authority: OpenTimestampsAuthority, proof_dir: Path
) -> None:
    (proof_dir / COMPLETE_FILE).write_bytes(
        (DATA / "hello-world.txt.ots").read_bytes()
    )
    (proof_dir / COMPLETE_FILE).rename(proof_dir / PENDING_FILE)
    root = hashlib.sha256((DATA / "hello-world.txt").read_bytes()).hexdigest()
    with pytest.raises(VaultError, match="names no calendar"):
        await authority.verify(root, proof_dir)


async def test_calendar_failure_at_stamp_names_the_authority(
    authority: OpenTimestampsAuthority, proof_dir: Path, calendar: LocalCalendar
) -> None:
    calendar.misbehave = "http500"
    with pytest.raises(VaultError, match="authority ots: .*answered HTTP 500"):
        await authority.stamp(ROOT, SEALED, proof_dir)
    assert files(proof_dir) == set()


async def test_explorer_without_the_block_fails_completion(
    authority: OpenTimestampsAuthority,
    proof_dir: Path,
    calendar: LocalCalendar,
) -> None:
    await authority.stamp(ROOT, SEALED, proof_dir)
    calendar.mine(HEIGHT, MINED)
    with pytest.raises(VaultError, match=f"block-height/{HEIGHT} answered"):
        await authority.complete(ROOT, proof_dir)
    assert files(proof_dir) == {PENDING_FILE, STAMP_FILE}
