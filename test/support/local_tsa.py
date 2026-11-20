"""A real RFC 3161 authority for tests: the committed CA and timestamping
certificate under data/tsa, and an HTTP server that answers queries by
running `openssl ts -reply`. Nothing is faked; only the trust anchor is
ours. The committed files are read in place; everything OpenSSL writes
goes under a pytest directory."""

import asyncio
from pathlib import Path

from aiohttp import web

from vault.authorities.rfc3161 import QUERY_TYPE, REPLY_TYPE, openssl

DATA = Path(__file__).resolve().parent / "data" / "tsa"
CHAIN = DATA / "ca.pem"


def write_config(workdir: Path) -> Path:
    """OpenSSL `ts` configuration pointing at the committed material and
    keeping its serial counter in `workdir`."""
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "serial").write_text("01\n")
    config = workdir / "tsa.cnf"
    config.write_text(
        "[ tsa ]\n"
        "default_tsa = tsa_config1\n"
        "[ tsa_config1 ]\n"
        f"serial = {workdir}/serial\n"
        f"signer_cert = {DATA}/tsa.pem\n"
        f"signer_key = {DATA}/tsa.key\n"
        "signer_digest = sha256\n"
        f"certs = {CHAIN}\n"
        "default_policy = 1.3.6.1.4.1.99999.1\n"
        "digests = sha256, sha512\n"
        "accuracy = secs:1\n"
        "ordering = no\n"
        "tsa_name = yes\n"
        "ess_cert_id_chain = no\n"
        "ess_cert_id_alg = sha256\n"
    )
    return config


class LocalTsa:
    """HTTP front of the OpenSSL authority. `misbehave` selects a failure
    mode for error-path tests: 'http500' or 'garbage'."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.config = write_config(workdir)
        self.misbehave: str | None = None
        self.requests: list[bytes] = []
        self._runner: web.AppRunner | None = None
        self.url = ""

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        body = await request.read()
        self.requests.append(body)
        if self.misbehave == "http500":
            return web.Response(status=500, text="tsa down")
        if self.misbehave == "garbage":
            return web.Response(body=b"not a token", content_type=REPLY_TYPE)
        if request.content_type != QUERY_TYPE:
            return web.Response(status=415, text="unexpected content type")
        n = len(self.requests)
        query = self.workdir / f"request-{n}.tsq"
        reply = self.workdir / f"reply-{n}.tsr"
        await asyncio.to_thread(query.write_bytes, body)
        await openssl(
            "ts", "-reply", "-config", str(self.config),
            "-queryfile", str(query), "-out", str(reply),
        )  # fmt: skip
        return web.Response(body=reply.read_bytes(), content_type=REPLY_TYPE)

    async def start(self) -> None:
        app = web.Application()
        app.router.add_post("/", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        assert self._runner.addresses
        host, port = self._runner.addresses[0][:2]
        self.url = f"http://{host}:{port}/"

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
