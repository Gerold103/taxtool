"""An OpenTimestamps calendar for tests, speaking the real wire protocol
in one process.

It accepts digests as the public calendars do and keeps them pending
until `mine` is called, which anchors every pending commitment in one
new block: a merkle tree over the commitments, a transaction carrying
its tip, the block's merkle tree, and a header that passes its own proof
of work at a trivial difficulty. The header is returned for the test to
hand to a `LocalExplorer`; this class knows nothing of explorers. Only
Bitcoin itself is replaced; the bytes a client sees are what a real
calendar would send.
"""

import os
import struct
from datetime import UTC, datetime
from http import HTTPStatus

from aiohttp import web

from vault.bitcoin.header import BlockHeader
from vault.ots.attestation import Bitcoin, Pending
from vault.ots.ops import TAG_APPEND, TAG_PREPEND, TAG_SHA256, Op
from vault.ots.tree import Node

OCTETS = "application/octet-stream"
# What the public calendars answer with 404 while a digest waits.
PENDING_TEXT = "Pending confirmation in Bitcoin blockchain"
# The easiest target the compact encoding allows: exponent 0x20 puts the
# 23-bit mantissa 0x7fffff at the top of the 256-bit range, so about
# half of all hashes pass and a nonce is found within a few tries.
EASY_BITS = 0x207FFFFF
SHA256 = Op(TAG_SHA256)
NONCE_SIZE = 16
MAC_SIZE = 8
TIME_FORMAT = ">L"


def join(left: Node, right: Node) -> Node:
    """One merkle level: both nodes lead to their concatenation, which
    is then hashed, as the reference merkle tree does."""
    concatenated = left.step(Op(TAG_APPEND, right.msg))
    right.ops[Op(TAG_PREPEND, left.msg)] = concatenated
    return concatenated.step(SHA256)


def merkle_tree(leaves: list[Node]) -> Node:
    level = leaves
    while len(level) > 1:
        pairs = zip(level[::2], level[1::2], strict=False)
        paired = [join(a, b) for a, b in pairs]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return level[0]


def mine_header(block_root: bytes, time: datetime) -> BlockHeader:
    previous = os.urandom(32)
    for nonce in range(2**32):
        header = BlockHeader(
            2, previous, block_root, int(time.timestamp()), EASY_BITS, nonce
        )
        if int(header.hash, 16) <= header.target:
            return header
    raise AssertionError("no nonce satisfied the easiest target")


class LocalCalendar:
    """`misbehave` is None, 'http500', 'garbage' (not a proof),
    'too-long' (a body over the client's limit) or 'bad-header' (a mined
    header whose merkle root is not the proofs' final message)."""

    def __init__(self) -> None:
        self.url = ""
        self.misbehave: str | None = None
        self.pending_text = PENDING_TEXT
        self.requests: list[tuple[str, str, str | None]] = []
        self.pending: dict[bytes, Node] = {}
        self.complete: dict[bytes, Node] = {}
        self._runner: web.AppRunner | None = None

    def _record(self, request: web.Request) -> None:
        accept = request.headers.get("Accept")
        self.requests.append((request.method, request.path, accept))

    async def _digest(self, request: web.Request) -> web.StreamResponse:
        self._record(request)
        digest = await request.read()
        if self.misbehave == "http500":
            return web.Response(status=500, text="calendar down")
        if self.misbehave == "garbage":
            return web.Response(body=b"not a proof", content_type=OCTETS)
        if self.misbehave == "too-long":
            return web.Response(body=b"\xff" * 10001, content_type=OCTETS)
        # Every `step` writes one operation into the node it is called
        # on and returns the node that operation leads to, so these lines
        # grow a path out of `root`. The aggregator's part: a nonce, so
        # that no customer's digest appears in another's proof, hashed.
        root = Node(digest)
        nonced = root.step(Op(TAG_APPEND, os.urandom(NONCE_SIZE)))
        leaf = nonced.step(SHA256)
        # The calendar's part: the submission time and an authenticator
        # by which it recognizes its own commitments later.
        now = int(datetime.now(UTC).timestamp())
        timed = leaf.step(Op(TAG_PREPEND, struct.pack(TIME_FORMAT, now)))
        commitment = timed.step(Op(TAG_APPEND, os.urandom(MAC_SIZE)))
        commitment.attestations.add(Pending(self.url))
        # What `mine` will grow the rest of the path out of, and what
        # `_timestamp` serializes once it is there.
        self.pending[commitment.msg] = Node(commitment.msg)
        return web.Response(body=root.serialize(), content_type=OCTETS)

    async def _timestamp(self, request: web.Request) -> web.StreamResponse:
        self._record(request)
        commitment = bytes.fromhex(request.match_info["hex"])
        if commitment in self.complete:
            body = self.complete[commitment].serialize()
            return web.Response(body=body, content_type=OCTETS)
        text = self.pending_text if commitment in self.pending else "Not found"
        return web.Response(status=HTTPStatus.NOT_FOUND, text=text)

    def mine(self, height: int, time: datetime) -> BlockHeader:
        """Anchor every pending commitment in one new block at `height`
        and return its header."""
        # The calendar's merkle tree over every pending commitment. Each
        # `step` and `join` writes into the commitment nodes stored in
        # `self.pending`, and all their paths converge on one node, the
        # calendar root. That is the one hash the calendar puts into
        # Bitcoin.
        commitments = list(self.pending.values())
        leaves = [commitment.step(SHA256) for commitment in commitments]
        calendar_root = merkle_tree(leaves)
        # One transaction carries the calendar root somewhere in its
        # bytes; the prepended and appended bytes are the rest of the
        # transaction, and the double hash is its id.
        prefixed = calendar_root.step(Op(TAG_PREPEND, os.urandom(20)))
        transaction = prefixed.step(Op(TAG_APPEND, os.urandom(10)))
        txid = transaction.step(SHA256).step(SHA256)
        # Bitcoin's merkle tree over the block's transactions, one level
        # here: the appended bytes are a sibling transaction's id, and
        # the double hash of the pair is the block root in the header.
        paired = txid.step(Op(TAG_APPEND, os.urandom(32)))
        block_root = paired.step(SHA256).step(SHA256)
        block_root.attestations.add(Bitcoin(height))
        if self.misbehave == "bad-header":
            header = mine_header(os.urandom(32), time)
        else:
            header = mine_header(block_root.msg, time)
        # Every commitment node now holds a path to `block_root`, so
        # `_timestamp` can answer with it instead of a 404.
        for msg, commitment in self.pending.items():
            self.complete[msg] = commitment
        self.pending.clear()
        return header

    async def start(self) -> None:
        app = web.Application()
        app.router.add_post("/digest", self._digest)
        app.router.add_get("/timestamp/{hex}", self._timestamp)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        assert self._runner.addresses
        host, port = self._runner.addresses[0][:2]
        self.url = f"http://{host}:{port}"

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
