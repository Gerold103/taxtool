import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from support.local_calendar import PENDING_TEXT, LocalCalendar
from vault.errors import VaultError
from vault.ots.attestation import Bitcoin, Pending
from vault.ots.calendar import (
    ACCEPT,
    REASON_LENGTH,
    Waiting,
    fetch,
    sanitize_reason,
    submit,
)
from vault.ots.tree import Node

DIGEST = hashlib.sha256(b"a seal").digest()
HEIGHT = 900_000
TIME = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.fixture
async def calendar() -> AsyncIterator[LocalCalendar]:
    server = LocalCalendar()
    await server.start()
    yield server
    await server.stop()


def commitment_of(root: Node) -> Node:
    """The one node of `root`'s tree that carries a pending attestation."""
    nodes = [n for n, a in root.all_attestations() if isinstance(a, Pending)]
    assert len(nodes) == 1
    return nodes[0]


async def test_submit_returns_a_path_ending_in_a_pending_attestation(
    calendar: LocalCalendar,
) -> None:
    root = await submit(calendar.url, DIGEST)
    assert root.msg == DIGEST
    assert commitment_of(root).attestations == {Pending(calendar.url)}
    assert calendar.requests == [("POST", "/digest", ACCEPT)]


async def test_submit_accepts_a_trailing_slash(calendar: LocalCalendar) -> None:
    root = await submit(calendar.url + "/", DIGEST)
    assert root.msg == DIGEST
    assert calendar.requests == [("POST", "/digest", ACCEPT)]


async def test_fetch_before_the_block_is_waiting(
    calendar: LocalCalendar,
) -> None:
    root = await submit(calendar.url, DIGEST)
    commitment = commitment_of(root)
    answer = await fetch(calendar.url, commitment.msg)
    assert answer == Waiting(PENDING_TEXT)
    assert calendar.requests[1] == (
        "GET",
        f"/timestamp/{commitment.msg.hex()}",
        ACCEPT,
    )


async def test_fetch_after_the_block_completes_the_path(
    calendar: LocalCalendar,
) -> None:
    root = await submit(calendar.url, DIGEST)
    header = calendar.mine(HEIGHT, TIME)
    commitment = commitment_of(root)
    answer = await fetch(calendar.url, commitment.msg)
    assert isinstance(answer, Node)
    commitment.merge(answer)
    final = [n for n, a in root.all_attestations() if a == Bitcoin(HEIGHT)]
    assert len(final) == 1
    assert final[0].msg == header.merkle_root
    assert commitment.attestations == {Pending(calendar.url)}


async def test_many_digests_share_one_block(calendar: LocalCalendar) -> None:
    digests = [hashlib.sha256(bytes([i])).digest() for i in range(5)]
    roots = [await submit(calendar.url, d) for d in digests]
    header = calendar.mine(HEIGHT, TIME)
    for root in roots:
        commitment = commitment_of(root)
        answer = await fetch(calendar.url, commitment.msg)
        assert isinstance(answer, Node)
        commitment.merge(answer)
        final = [n for n, a in root.all_attestations() if a == Bitcoin(HEIGHT)]
        assert final[0].msg == header.merkle_root


async def test_unknown_commitment_is_waiting_with_the_calendars_words(
    calendar: LocalCalendar,
) -> None:
    assert await fetch(calendar.url, b"\x00" * 32) == Waiting("Not found")


async def test_reason_is_sanitized(calendar: LocalCalendar) -> None:
    calendar.pending_text = "line one\nline two: ünïcode" + "!" * 200
    root = await submit(calendar.url, DIGEST)
    answer = await fetch(calendar.url, commitment_of(root).msg)
    assert isinstance(answer, Waiting)
    # Each of the two non-ASCII letters is two UTF-8 bytes, two blanks.
    assert answer.reason.startswith("line one_line two_ __n__code")
    assert len(answer.reason) == REASON_LENGTH
    assert "\n" not in answer.reason


def test_sanitize_keeps_only_the_whitelist() -> None:
    assert sanitize_reason(b"ok #1, fine; done.") == "ok #1, fine; done."
    assert sanitize_reason(b"a\tb\x00c<d>") == "a_b_c_d_"
    assert sanitize_reason(b"") == ""


async def test_http_error_is_reported(calendar: LocalCalendar) -> None:
    calendar.misbehave = "http500"
    with pytest.raises(VaultError, match="/digest answered HTTP 500"):
        await submit(calendar.url, DIGEST)


async def test_garbage_answer_is_reported(calendar: LocalCalendar) -> None:
    calendar.misbehave = "garbage"
    with pytest.raises(VaultError, match="answered with an invalid proof"):
        await submit(calendar.url, DIGEST)


async def test_oversized_answer_is_refused(calendar: LocalCalendar) -> None:
    calendar.misbehave = "too-long"
    with pytest.raises(VaultError, match="answered with too much data"):
        await submit(calendar.url, DIGEST)


async def test_unreachable_calendar_is_reported(
    calendar: LocalCalendar,
) -> None:
    url = calendar.url
    await calendar.stop()
    with pytest.raises(VaultError, match=f"request to {url}/digest failed"):
        await submit(url, DIGEST)
