"""An authority that anchors the root hash in Bitcoin through an
OpenTimestamps calendar.

The calendar takes the hash at once and puts a batch of hashes into one
Bitcoin transaction some hours later, so a proof is born Pending and is
finished by `complete`. Files of a proof directory:

    root.pending.ots  what the calendar answered at sealing time, never
                      touched again
    root.ots          the full path from the root hash to a block's
                      merkle root, added by complete
    block-header.bin  the 80-byte header of that block, added by complete
    stamp.yaml        who was asked and when, the `since` while pending

Verification is offline: the proof must be about the root hash, end in
exactly one Bitcoin attestation whose message is the merkle root of the
saved header, and the header must pass its own proof of work. The time
attested is the block time. What cannot be checked offline is that the
saved header is the block at that height; an auditor confirms its hash
against any explorer or node, see doc/risks.md.
"""

import asyncio
from datetime import datetime
from pathlib import Path

import yaml

from vault.authorities import Complete, Pending, check_root, check_time
from vault.bitcoin.explorer import fetch_header
from vault.bitcoin.header import BlockHeader
from vault.errors import VaultError
from vault.ots import attestation, calendar
from vault.ots.file import parse_file, serialize_file
from vault.ots.tree import Node

TYPE = "opentimestamps"
PENDING_FILE = "root.pending.ots"
COMPLETE_FILE = "root.ots"
HEADER_FILE = "block-header.bin"
STAMP_FILE = "stamp.yaml"
PENDING_WHY = "waiting for the calendar to anchor the hash in a Bitcoin block"


class OpenTimestampsAuthority:
    def __init__(self, name: str, calendar: str, explorer: str) -> None:
        """`calendar` is the calendar or aggregator to submit to;
        `explorer` an Esplora-style API serving block headers."""
        self.name = name
        self.calendar = calendar
        self.explorer = explorer

    def _error(self, what: str) -> VaultError:
        return VaultError(f"authority {self.name}: {what}")

    # Pending attestations and the Bitcoin anchor of a proof.

    def _pending(self, proof: Node) -> list[tuple[Node, attestation.Pending]]:
        return [
            (node, a)
            for node, a in proof.all_attestations()
            if isinstance(a, attestation.Pending)
        ]

    def _anchor(self, proof: Node) -> tuple[Node, attestation.Bitcoin] | None:
        """The proof's one Bitcoin attestation with the node it is about,
        whose message a block's merkle root must equal. One calendar
        yields one, so several are an error, not a choice."""
        anchors = [
            (node, a)
            for node, a in proof.all_attestations()
            if isinstance(a, attestation.Bitcoin)
        ]
        if len(anchors) > 1:
            raise self._error(f"proof has {len(anchors)} Bitcoin attestations")
        return anchors[0] if anchors else None

    def _attested_time(self, proof: Node, header: BlockHeader) -> datetime:
        """The block time, once the proof ends in the header's merkle
        root."""
        anchor = self._anchor(proof)
        if anchor is None:
            raise self._error("proof has no Bitcoin attestation")
        node, bitcoin = anchor
        if node.msg != header.merkle_root:
            raise self._error(
                "the proof ends in a hash that is not the merkle root of "
                f"the saved header for block {bitcoin.height}"
            )
        return header.time

    # Files of the proof directory.

    def _read_proof(self, path: Path, root: str) -> Node:
        if not path.is_file():
            raise self._error(f"no proof at {path}")
        try:
            proof = parse_file(path.read_bytes())
        except VaultError as exc:
            raise self._error(f"{path} is not a valid proof: {exc}") from exc
        if proof.msg != bytes.fromhex(root):
            raise self._error(
                f"{path} is for hash {proof.msg.hex()}, not {root}"
            )
        return proof

    def _read_header(self, proof_dir: Path) -> BlockHeader:
        path = proof_dir / HEADER_FILE
        if not path.is_file():
            raise self._error(f"{path} is missing")
        try:
            header = BlockHeader.parse(path.read_bytes())
            header.check()
        except VaultError as exc:
            raise self._error(f"{path}: {exc}") from exc
        return header

    def _read_since(self, proof_dir: Path) -> datetime:
        path = proof_dir / STAMP_FILE
        try:
            record = yaml.safe_load(path.read_text(encoding="utf-8"))
            time = record["time"]
            if record["type"] != TYPE or not isinstance(time, str):
                raise ValueError("wrong type")
            return check_time(datetime.fromisoformat(time))
        except (OSError, TypeError, KeyError, ValueError) as exc:
            raise self._error(f"{path} is missing or malformed: {exc}") from exc

    def _write_pending(
        self, proof_dir: Path, proof: Node, since: datetime
    ) -> None:
        record = {
            "type": TYPE,
            "authority": self.name,
            "calendar": self.calendar,
            "time": since.isoformat(),
        }
        text = yaml.safe_dump(record, sort_keys=False)
        (proof_dir / PENDING_FILE).write_bytes(serialize_file(proof))
        (proof_dir / STAMP_FILE).write_text(text, encoding="utf-8")

    def _write_complete(
        self, proof_dir: Path, proof: Node, header: BlockHeader
    ) -> None:
        (proof_dir / HEADER_FILE).write_bytes(header.raw)
        (proof_dir / COMPLETE_FILE).write_bytes(serialize_file(proof))

    # The protocol.

    async def stamp(self, root: str, now: datetime, proof_dir: Path) -> Pending:
        digest = bytes.fromhex(check_root(root))
        since = check_time(now)
        try:
            proof = await calendar.submit(self.calendar, digest)
        except VaultError as exc:
            raise self._error(str(exc)) from exc
        if not self._pending(proof):
            raise self._error(f"{self.calendar} returned no pending proof")
        await asyncio.to_thread(self._write_pending, proof_dir, proof, since)
        return Pending(since, PENDING_WHY)

    async def _ask_calendars(self, proof: Node) -> list[str]:
        """Graft each calendar's answer onto the node it was asked about;
        return the reasons of those that have no block yet."""
        reasons = []
        for node, pending in self._pending(proof):
            try:
                answer = await calendar.fetch(pending.uri, node.msg)
            except VaultError as exc:
                raise self._error(str(exc)) from exc
            if isinstance(answer, calendar.Waiting):
                reasons.append(f"{pending.uri}: {answer.reason}")
            else:
                node.merge(answer)
        return reasons

    async def complete(self, root: str, proof_dir: Path) -> Complete | Pending:
        if (proof_dir / COMPLETE_FILE).is_file():
            return await self.verify(root, proof_dir)
        proof = await asyncio.to_thread(
            self._read_proof, proof_dir / PENDING_FILE, root
        )
        since = await asyncio.to_thread(self._read_since, proof_dir)
        reasons = await self._ask_calendars(proof)
        anchor = self._anchor(proof)
        if anchor is None:
            return Pending(since, "; ".join(reasons) or PENDING_WHY)
        try:
            header = await fetch_header(self.explorer, anchor[1].height)
        except VaultError as exc:
            raise self._error(str(exc)) from exc
        # Checked in memory first, so that nothing invalid is ever written
        # into a directory a seal will cover; then reported from the files
        # like any later verify would.
        self._attested_time(proof, header)
        await asyncio.to_thread(self._write_complete, proof_dir, proof, header)
        return await self.verify(root, proof_dir)

    def _verify(self, root: str, proof_dir: Path) -> Complete | Pending:
        check_root(root)
        if (proof_dir / COMPLETE_FILE).is_file():
            proof = self._read_proof(proof_dir / COMPLETE_FILE, root)
            header = self._read_header(proof_dir)
            return Complete(self._attested_time(proof, header))
        proof = self._read_proof(proof_dir / PENDING_FILE, root)
        if not self._pending(proof):
            raise self._error(f"{proof_dir / PENDING_FILE} names no calendar")
        return Pending(self._read_since(proof_dir), PENDING_WHY)

    async def verify(self, root: str, proof_dir: Path) -> Complete | Pending:
        return await asyncio.to_thread(self._verify, root, proof_dir)
