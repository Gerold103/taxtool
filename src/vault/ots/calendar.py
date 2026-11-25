"""The HTTP client of a calendar, as in the reference client's
calendar.py.

A calendar answers two questions. `POST /digest` with our digest as
the body: it adds the digest to its current batch and returns the path
from our digest to its commitment, the node that ends in a pending
attestation naming the calendar. `GET /timestamp/<commitment in hex>`:
once the batch is in a Bitcoin block it returns the path from the
commitment to the block's merkle root, ending in a Bitcoin attestation;
until then it answers 404 with a one-line reason.

Both answers are a serialized node for the message asked about, so the
caller grafts them onto its own tree with `Node.merge`. A calendar is
not trusted: its answers are parsed with the same limits as a file from
disk, and a 404 reason is cut to the length and characters the
reference client allows before it can reach a terminal.
"""

from dataclasses import dataclass
from http import HTTPStatus

import aiohttp

from vault.errors import VaultError
from vault.ots.tree import Node, parse_node

ACCEPT = "application/vnd.opentimestamps.v1"
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30)
# A complete path is a couple of thousand bytes; the reference client
# refuses more than this.
MAX_RESPONSE = 10000
# The reference client reads this much of a 404 body and replaces every
# byte outside the whitelist with an underscore. Newlines are out on
# purpose, so that a hostile calendar cannot forge lines of output.
REASON_LENGTH = 160
REASON_CHARS = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#-.,; "
)
REASON_REPLACEMENT = ord("_")


@dataclass(frozen=True)
class Waiting:
    """The calendar has the commitment but no block for it yet."""

    reason: str


def sanitize_reason(body: bytes) -> str:
    return bytes(
        byte if byte in REASON_CHARS else REASON_REPLACEMENT
        for byte in body[:REASON_LENGTH]
    ).decode()


async def _request(
    session: aiohttp.ClientSession, method: str, url: str, body: bytes | None
) -> tuple[int, bytes]:
    try:
        async with session.request(
            method, url, data=body, headers={"Accept": ACCEPT}
        ) as resp:
            data = await resp.content.read(MAX_RESPONSE + 1)
    except aiohttp.ClientError as exc:
        raise VaultError(f"request to {url} failed: {exc}") from exc
    if len(data) > MAX_RESPONSE:
        raise VaultError(f"{url} answered with too much data")
    return resp.status, data


def _parse(url: str, data: bytes, msg: bytes) -> Node:
    try:
        return parse_node(data, msg)
    except VaultError as exc:
        raise VaultError(
            f"{url} answered with an invalid proof: {exc}"
        ) from exc


async def submit(calendar: str, digest: bytes) -> Node:
    """Send `digest` to the calendar at the base URL `calendar`; the
    answer is the node for `digest` that ends in a pending attestation."""
    url = f"{calendar.rstrip('/')}/digest"
    async with aiohttp.ClientSession(timeout=HTTP_TIMEOUT) as session:
        status, data = await _request(session, "POST", url, digest)
    if status != HTTPStatus.OK:
        raise VaultError(f"{url} answered HTTP {status}")
    return _parse(url, data, digest)


async def fetch(uri: str, commitment: bytes) -> Node | Waiting:
    """Ask the calendar at `uri`, the one a pending attestation names,
    for the rest of the path from `commitment`."""
    url = f"{uri.rstrip('/')}/timestamp/{commitment.hex()}"
    async with aiohttp.ClientSession(timeout=HTTP_TIMEOUT) as session:
        status, data = await _request(session, "GET", url, None)
    if status == HTTPStatus.NOT_FOUND:
        return Waiting(sanitize_reason(data))
    if status != HTTPStatus.OK:
        raise VaultError(f"{url} answered HTTP {status}")
    return _parse(url, data, commitment)
