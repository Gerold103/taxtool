#!/bin/bash
# Runs the test suite. Extra arguments go to pytest.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/tools/venv.sh"
cd "$TAXTOOL_ROOT"
exec pytest "$@"
