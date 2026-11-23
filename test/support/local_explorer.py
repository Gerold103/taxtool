"""A block explorer for tests: the two Esplora endpoints the vault uses,
serving whatever headers a test puts into `headers`."""

from http import HTTPStatus

from aiohttp import web

from vault.bitcoin.header import BlockHeader


class LocalExplorer:
    """`misbehave` is None, 'wrong-header' (a header that does not hash
    to the block hash) or 'garbage' (not hex at all)."""

    def __init__(self) -> None:
        self.url = ""
        self.headers: dict[int, BlockHeader] = {}
        self.misbehave: str | None = None
        self.requests: list[str] = []
        self._runner: web.AppRunner | None = None

    async def _block_height(self, request: web.Request) -> web.StreamResponse:
        self.requests.append(request.path)
        header = self.headers.get(int(request.match_info["height"]))
        if header is None:
            return web.Response(status=HTTPStatus.NOT_FOUND, text="no block")
        return web.Response(text=header.hash)

    async def _header(self, request: web.Request) -> web.StreamResponse:
        self.requests.append(request.path)
        if self.misbehave == "garbage":
            return web.Response(text="not hex")
        for header in self.headers.values():
            if header.hash == request.match_info["hash"]:
                if self.misbehave == "wrong-header":
                    header = BlockHeader.parse(header.raw[::-1])
                return web.Response(text=header.raw.hex())
        return web.Response(status=HTTPStatus.NOT_FOUND, text="no block")

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/block-height/{height}", self._block_height)
        app.router.add_get("/block/{hash}/header", self._header)
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
