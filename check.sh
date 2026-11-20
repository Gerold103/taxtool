#!/bin/bash
# Everything a commit must pass: formatting, lint, types, tests.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/tools/venv.sh"
cd "$TAXTOOL_ROOT"
ruff format --check src test
ruff check src test
mypy
pytest
# Every tracked text file keeps to 80 columns.
if git ls-files -z | xargs -0 awk 'length > 80 {print FILENAME ":" FNR}' \
    | grep .; then
    echo "lines over 80 columns" >&2
    exit 1
fi
