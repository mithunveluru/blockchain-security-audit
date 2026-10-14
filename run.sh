#!/usr/bin/env bash
# ./run.sh            live capture (needs cap_net_raw or root)
# ./run.sh --sim      simulation mode, no privileges, synthetic traffic only
# ./run.sh --setcap   grant raw capture capability to the python interpreter, then exit
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
    if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi
fi

case "${1:-}" in
    --sim) export ENABLE_SIMULATION_MODE=1 ;;
    --setcap)
        REAL="$(readlink -f "$(command -v "$PY")")"
        echo "granting cap_net_raw,cap_net_admin to $REAL (needs sudo)"
        exec sudo setcap cap_net_raw,cap_net_admin=eip "$REAL" ;;
    "") ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

exec "$PY" enhanced_network_app.py
