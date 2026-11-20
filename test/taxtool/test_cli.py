import asyncio
import threading
import time

import pytest

from taxtool import VERSION
from taxtool.cli import THREAD_POOL_SIZE, limit_thread_pool, main


async def test_no_arguments_succeeds() -> None:
    assert await main([]) == 0


async def test_version_prints_and_exits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as info:
        await main(["--version"])
    assert info.value.code == 0
    assert capsys.readouterr().out.strip() == f"taxtool {VERSION}"


async def test_thread_pool_runs_at_most_two_at_once() -> None:
    limit_thread_pool()
    running = 0
    peak = 0
    lock = threading.Lock()

    def work() -> None:
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.05)
        with lock:
            running -= 1

    await asyncio.gather(*(asyncio.to_thread(work) for _ in range(6)))
    assert peak == THREAD_POOL_SIZE
