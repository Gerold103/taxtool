import asyncio
import sys

from taxtool.cli import main

raise SystemExit(asyncio.run(main(sys.argv[1:])))
