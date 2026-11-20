# Sourced by tax, test.sh and check.sh. Creates .venv on first use and
# reinstalls the requirements whenever they change. Sets TAXTOOL_ROOT.

TAXTOOL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv="$TAXTOOL_ROOT/.venv"
wanted="$TAXTOOL_ROOT/requirements.txt"
wanted_dev="$TAXTOOL_ROOT/requirements-dev.txt"
installed="$venv/installed-requirements.txt"

if [ ! -x "$venv/bin/python" ]; then
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 13))'
    then
        echo "taxtool needs python3 >= 3.13, found: $(python3 --version)" >&2
        exit 1
    fi
    python3 -m venv "$venv"
fi

if ! cat "$wanted" "$wanted_dev" | cmp -s - "$installed"; then
    "$venv/bin/pip" install -q --disable-pip-version-check \
        -r "$wanted" -r "$wanted_dev"
    cat "$wanted" "$wanted_dev" > "$installed"
fi

# shellcheck disable=SC1091
. "$venv/bin/activate"
