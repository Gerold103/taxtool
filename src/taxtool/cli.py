import argparse

from taxtool import VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tax", description="Local, sealed bookkeeping."
    )
    parser.add_argument(
        "--version", action="version", version=f"taxtool {VERSION}"
    )
    return parser


async def main(argv: list[str]) -> int:
    build_parser().parse_args(argv)
    return 0
