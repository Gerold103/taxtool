import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor

from taxtool import VERSION

# File hashing and copying run on this pool via asyncio.to_thread. The tool
# handles a few documents per session; two workers keep it light while one
# large file never blocks a second small one.
THREAD_POOL_SIZE = 2


def limit_thread_pool() -> None:
    """Replace the loop's default executor with a two-thread pool."""
    pool = ThreadPoolExecutor(
        max_workers=THREAD_POOL_SIZE, thread_name_prefix="taxtool-io"
    )
    asyncio.get_running_loop().set_default_executor(pool)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tax", description="Local, sealed bookkeeping."
    )
    parser.add_argument(
        "--version", action="version", version=f"taxtool {VERSION}"
    )
    return parser


async def main(argv: list[str]) -> int:
    limit_thread_pool()
    build_parser().parse_args(argv)
    return 0
