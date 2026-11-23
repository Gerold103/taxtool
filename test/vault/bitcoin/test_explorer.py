from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from support.local_explorer import LocalExplorer
from vault.bitcoin.explorer import fetch_header
from vault.bitcoin.header import BlockHeader
from vault.errors import VaultError

DATA = Path(__file__).resolve().parents[2] / "support" / "data" / "ots"
HEADER = BlockHeader.parse((DATA / "block-358391.bin").read_bytes())


@pytest.fixture
async def server() -> AsyncIterator[LocalExplorer]:
    explorer = LocalExplorer()
    explorer.headers[358391] = HEADER
    await explorer.start()
    yield explorer
    await explorer.stop()


async def test_header_is_fetched_by_height(server: LocalExplorer) -> None:
    assert await fetch_header(server.url + "/", 358391) == HEADER
    assert server.requests == [
        "/block-height/358391",
        f"/block/{HEADER.hash}/header",
    ]


async def test_unknown_height_is_reported(server: LocalExplorer) -> None:
    with pytest.raises(VaultError, match="block-height/1 answered HTTP 404"):
        await fetch_header(server.url, 1)


async def test_header_not_matching_the_hash_is_rejected(
    server: LocalExplorer,
) -> None:
    server.misbehave = "wrong-header"
    with pytest.raises(VaultError, match="does not hash to"):
        await fetch_header(server.url, 358391)


async def test_garbage_is_rejected(server: LocalExplorer) -> None:
    server.misbehave = "garbage"
    with pytest.raises(VaultError, match="unreadable"):
        await fetch_header(server.url, 358391)


async def test_unreachable_explorer_is_reported() -> None:
    server = LocalExplorer()
    await server.start()
    url = server.url
    await server.stop()
    with pytest.raises(VaultError, match="request to .* failed"):
        await fetch_header(url, 358391)
