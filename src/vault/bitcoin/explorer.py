"""Fetch a block header by height from an Esplora-style HTTP API.

blockstream.info, mempool.space and self-hosted Esplora instances all
answer `GET /block-height/<h>` with the block hash and `GET
/block/<hash>/header` with the 80 header bytes in hex. The header is
checked to hash to the block hash it was asked by and to pass its proof
of work, so a lying or broken explorer is caught here.
"""

from http import HTTPStatus

import aiohttp

from vault.bitcoin.header import BlockHeader
from vault.errors import VaultError

HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30)
# A hash is 64 characters and a header 160; anything much longer is not
# an answer to our question.
MAX_RESPONSE = 1000


async def _get(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url) as resp:
            body = await resp.content.read(MAX_RESPONSE + 1)
    except aiohttp.ClientError as exc:
        raise VaultError(f"request to {url} failed: {exc}") from exc
    if resp.status != HTTPStatus.OK:
        raise VaultError(f"{url} answered HTTP {resp.status}")
    if len(body) > MAX_RESPONSE:
        raise VaultError(f"{url} answered with too much data")
    return body.decode(errors="replace").strip()


async def fetch_header(explorer: str, height: int) -> BlockHeader:
    """The header of the block at `height`, from the explorer at the
    base URL `explorer`, checked against its own hash and target."""
    base = explorer.rstrip("/")
    async with aiohttp.ClientSession(timeout=HTTP_TIMEOUT) as session:
        block_hash = await _get(session, f"{base}/block-height/{height}")
        text = await _get(session, f"{base}/block/{block_hash}/header")
    try:
        header = BlockHeader.parse(bytes.fromhex(text))
    except (ValueError, VaultError) as exc:
        raise VaultError(
            f"{base}: header of block {height} is unreadable: {exc}"
        ) from exc
    if header.hash != block_hash:
        raise VaultError(
            f"{base}: header of block {height} does not hash to {block_hash}"
        )
    header.check()
    return header
