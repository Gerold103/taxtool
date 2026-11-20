"""RFC 3161 timestamp authority, driven through `openssl ts`.

stamp builds a timestamp query for the root hash, posts it over HTTP and
stores the DER response as `token.tsr` next to the query. verify is
offline: OpenSSL checks the token's signature against the authority's
certificate chain saved locally, and the token's own time is used as the
validation time so that a signing certificate which expired since then
does not invalidate a proof made while it was valid.
"""

import asyncio
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import aiohttp

from vault.authorities import check_root
from vault.errors import VaultError

QUERY_FILE = "request.tsq"
TOKEN_FILE = "token.tsr"
QUERY_TYPE = "application/timestamp-query"
REPLY_TYPE = "application/timestamp-reply"
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30)
_TIME_LINE = re.compile(r"^Time stamp: (.+)$", re.MULTILINE)
_STATUS_LINE = re.compile(r"^Status: (.+)$", re.MULTILINE)


async def openssl(*args: str, binary: str = "openssl") -> bytes:
    """Run one openssl command; stdout on success, VaultError otherwise."""
    if shutil.which(binary) is None:
        raise VaultError(f"{binary} not found; it is needed for RFC 3161")
    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    if proc.returncode != 0:
        detail = err.decode(errors="replace").strip().splitlines()
        reason = detail[-1] if detail else f"exit code {proc.returncode}"
        raise VaultError(f"openssl {args[0]} failed: {reason}")
    return out


def parse_time(text: str) -> datetime:
    """The `Time stamp:` line of `openssl ts -reply -text`, as UTC."""
    match = _TIME_LINE.search(text)
    if not match:
        raise VaultError("timestamp token has no 'Time stamp' line")
    raw = match.group(1).strip()
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S.%f %Y GMT"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    raise VaultError(f"unreadable time in timestamp token: {raw!r}")


class Rfc3161Authority:
    def __init__(
        self, name: str, url: str, chain_file: Path, binary: str = "openssl"
    ) -> None:
        self.name = name
        self.url = url
        self.chain_file = chain_file
        self.binary = binary

    def _error(self, what: str) -> VaultError:
        return VaultError(f"authority {self.name}: {what}")

    async def _openssl(self, *args: str) -> bytes:
        try:
            return await openssl(*args, binary=self.binary)
        except VaultError as exc:
            raise self._error(str(exc)) from exc

    async def _post(self, query: bytes) -> bytes:
        headers = {"Content-Type": QUERY_TYPE, "Accept": REPLY_TYPE}
        try:
            async with (
                aiohttp.ClientSession(timeout=HTTP_TIMEOUT) as session,
                session.post(self.url, data=query, headers=headers) as resp,
            ):
                body = await resp.read()
                if resp.status != 200:
                    raise self._error(
                        f"{self.url} answered HTTP {resp.status}: "
                        f"{body[:200]!r}"
                    )
                return body
        except aiohttp.ClientError as exc:
            raise self._error(f"request to {self.url} failed: {exc}") from exc

    async def stamp(self, root: str, now: datetime, proof_dir: Path) -> None:
        check_root(root)
        query_path = proof_dir / QUERY_FILE
        token_path = proof_dir / TOKEN_FILE
        await self._openssl(
            "ts", "-query", "-digest", root, "-sha256", "-cert",
            "-out", str(query_path),
        )  # fmt: skip
        query = await asyncio.to_thread(query_path.read_bytes)
        token = await self._post(query)
        await asyncio.to_thread(token_path.write_bytes, token)
        # Trust nothing the server sent until it verifies locally.
        await self.verify(root, proof_dir)

    async def verify(self, root: str, proof_dir: Path) -> datetime:
        check_root(root)
        token_path = proof_dir / TOKEN_FILE
        if not token_path.is_file():
            raise self._error(f"no proof at {token_path}")
        if not self.chain_file.is_file():
            raise self._error(f"certificate chain {self.chain_file} missing")
        text = (
            await self._openssl("ts", "-reply", "-in", str(token_path), "-text")
        ).decode(errors="replace")
        status = _STATUS_LINE.search(text)
        if not status or not status.group(1).startswith("Granted"):
            got = status.group(1) if status else "no status"
            raise self._error(f"{token_path} was not granted: {got}")
        time = parse_time(text)
        await self._openssl(
            "ts", "-verify", "-digest", root, "-sha256",
            "-in", str(token_path),
            "-CAfile", str(self.chain_file),
            "-attime", str(int(time.timestamp())),
        )  # fmt: skip
        return time
