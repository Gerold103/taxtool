"""A self-issued authority for tests and examples.

The proof is an HMAC-SHA256 over the root hash and the time, keyed with a
secret the owner holds. It proves nothing to anyone else and exists so
that the whole sealing flow can run without a network.
"""

import asyncio
import hmac
from datetime import datetime
from hashlib import sha256
from pathlib import Path

import yaml

from vault.authorities import Complete, check_root, check_time
from vault.errors import VaultError

TYPE = "local-hmac-sha256"
TOKEN_FILE = "token.yaml"
NOTE = (
    "Self-issued proof for examples and tests. It proves nothing to third "
    "parties."
)


def message(root: str, time: str) -> bytes:
    return f"{root}\n{time}\n".encode()


class LocalHmacAuthority:
    def __init__(self, name: str, key_file: Path) -> None:
        self.name = name
        self.key_file = key_file

    def _key(self) -> bytes:
        try:
            text = self.key_file.read_text(encoding="utf-8").strip()
            key = bytes.fromhex(text)
        except (OSError, ValueError) as exc:
            raise VaultError(
                f"authority {self.name}: cannot read hex key from "
                f"{self.key_file}: {exc}"
            ) from exc
        if len(key) < 32:
            raise VaultError(
                f"authority {self.name}: key in {self.key_file} is shorter "
                "than 32 bytes"
            )
        return key

    def _mac(self, root: str, time: str) -> str:
        return hmac.new(self._key(), message(root, time), sha256).hexdigest()

    def _stamp(self, root: str, now: datetime, proof_dir: Path) -> None:
        time = check_time(now).isoformat()
        token = {
            "authority": self.name,
            "type": TYPE,
            "hash": check_root(root),
            "time": time,
            "message": "sha256 hex, newline, time, newline",
            "mac": self._mac(root, time),
            "note": NOTE,
        }
        # PyYAML breaks a long value only after passing the width; 60
        # leaves room for the overshoot so no line exceeds 80 columns.
        text = yaml.safe_dump(token, sort_keys=False, width=60)
        (proof_dir / TOKEN_FILE).write_text(text, encoding="utf-8")

    async def stamp(
        self, root: str, now: datetime, proof_dir: Path
    ) -> Complete:
        await asyncio.to_thread(self._stamp, root, now, proof_dir)
        return Complete(check_time(now))

    async def complete(self, root: str, proof_dir: Path) -> Complete:
        return await self.verify(root, proof_dir)

    def _verify(self, root: str, proof_dir: Path) -> Complete:
        path = proof_dir / TOKEN_FILE
        if not path.is_file():
            raise VaultError(f"authority {self.name}: no proof at {path}")
        token = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(token, dict) or token.get("type") != TYPE:
            raise VaultError(f"authority {self.name}: {path} is not a {TYPE}")
        if token.get("hash") != check_root(root):
            raise VaultError(
                f"authority {self.name}: {path} is for hash "
                f"{token.get('hash')}, not {root}"
            )
        time = token.get("time")
        mac = token.get("mac")
        if not isinstance(time, str) or not isinstance(mac, str):
            raise VaultError(f"authority {self.name}: {path} is malformed")
        if not hmac.compare_digest(self._mac(root, time), mac):
            raise VaultError(
                f"authority {self.name}: {path} has an invalid mac"
            )
        try:
            return Complete(check_time(datetime.fromisoformat(time)))
        except ValueError as exc:
            raise VaultError(
                f"authority {self.name}: {path} has an unreadable time"
            ) from exc

    async def verify(self, root: str, proof_dir: Path) -> Complete:
        return await asyncio.to_thread(self._verify, root, proof_dir)
