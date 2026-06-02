#!/usr/bin/env bash
# Usage:
#   ./run.sh                           # auto-detect python, check caps
#   ./run.sh --sim                     # force simulation mode
#   ./run.sh --setcap                  # grant cap_net_raw and exit
#   NETWORK_INTERFACE=eth0 ./run.sh    # specify interface

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

APP="enhanced_network_app.py"
SETCAP_BIN="${SETCAP_BIN:-/usr/sbin/setcap}"
GETCAP_BIN="${GETCAP_BIN:-/usr/sbin/getcap}"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[run.sh]${NC} $*"; }
ok()    { echo -e "${GREEN}[run.sh] ✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[run.sh] ⚠${NC} $*"; }
fatal() { echo -e "${RED}[run.sh] ✗${NC} $*" >&2; exit 1; }

FORCE_SIM=false
DO_SETCAP=false
for arg in "$@"; do
    case "$arg" in
        --sim)    FORCE_SIM=true ;;
        --setcap) DO_SETCAP=true ;;
    esac
done

find_python() {
    local candidates=(
        "${PYTHON:-}"
        "${CONDA_PREFIX:+$CONDA_PREFIX/bin/python}"
        "${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}"
        "$HOME/miniconda3/bin/python"
        "$HOME/anaconda3/bin/python"
        "/opt/conda/bin/python"
        "$(which python3 2>/dev/null || true)"
    )

    for py in "${candidates[@]}"; do
        [ -z "$py" ] && continue
        [ -f "$py" ] || [ -x "$py" ] || continue
        if "$py" -c "import flask, scapy" 2>/dev/null; then
            echo "$py"
            return 0
        fi
    done

    for py in "${candidates[@]}"; do
        [ -z "$py" ] && continue
        [ -f "$py" ] || [ -x "$py" ] || continue
        if "$py" -c "import flask" 2>/dev/null; then
            echo "$py"
            return 0
        fi
    done

    echo "$(which python3 2>/dev/null || echo python3)"
}

PYTHON="$(find_python)"
PYTHON_REAL="$(readlink -f "$PYTHON" 2>/dev/null || echo "$PYTHON")"

info "Python   : $PYTHON_REAL"
info "App      : $(pwd)/$APP"

MISSING_PKGS=""
for pkg in flask scapy numpy watchdog; do
    if ! "$PYTHON" -c "import $pkg" 2>/dev/null; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    warn "Missing packages in $PYTHON :$MISSING_PKGS"
    echo "  Install:  $PYTHON -m pip install$MISSING_PKGS"
    echo "  Or:       PYTHON=/home/mithunveluru/miniconda3/bin/python ./run.sh"
    echo ""
    CONDA_PY="$HOME/miniconda3/bin/python"
    if [ -f "$CONDA_PY" ] && [ "$CONDA_PY" != "$PYTHON" ]; then
        if "$CONDA_PY" -c "import flask, scapy" 2>/dev/null; then
            warn "Packages found in conda Python: $CONDA_PY"
            warn "Switching to conda Python..."
            PYTHON="$CONDA_PY"
            PYTHON_REAL="$(readlink -f "$PYTHON")"
        fi
    fi
fi

if $DO_SETCAP; then
    info "Granting cap_net_raw,cap_net_admin to $PYTHON_REAL ..."
    sudo "$SETCAP_BIN" cap_net_raw,cap_net_admin=eip "$PYTHON_REAL" && \
        ok "Capabilities granted. You can now run: ./run.sh" || \
        fatal "setcap failed. Try: sudo $SETCAP_BIN cap_net_raw,cap_net_admin=eip $PYTHON_REAL"
    exit 0
fi

if $FORCE_SIM; then
    warn "Simulation mode forced via --sim flag"
    export ENABLE_SIMULATION_MODE=true
    exec "$PYTHON" "$APP"
fi

CAN_CAPTURE="$("$PYTHON" -c "
import socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0); s.close(); print('yes')
except PermissionError:
    print('no')
" 2>/dev/null)"

if [ "$CAN_CAPTURE" = "yes" ]; then
    ok "Packet capture: READY"
    exec "$PYTHON" "$APP"
fi

warn "Raw socket permission denied for $PYTHON_REAL"
echo ""
echo "  Option 1 (recommended): grant caps once, no sudo needed after"
echo "    sudo $SETCAP_BIN cap_net_raw,cap_net_admin=eip $PYTHON_REAL && ./run.sh"
echo ""
echo "  Option 2: sudo with explicit interpreter"
echo "    sudo $PYTHON_REAL $APP"
echo ""
echo "  Option 3: simulation mode"
echo "    ./run.sh --sim"
echo ""

if [ -t 0 ]; then
    read -r -p "$(echo -e "${CYAN}Apply setcap now? Requires sudo password [y/N]:${NC} ")" choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        sudo "$SETCAP_BIN" cap_net_raw,cap_net_admin=eip "$PYTHON_REAL" && \
            ok "Capabilities granted." && exec "$PYTHON" "$APP" || \
            warn "setcap failed. Continuing with simulation mode."
    fi
fi

warn "Starting in SIMULATION MODE (no real packet capture)."
export ENABLE_SIMULATION_MODE=true
exec "$PYTHON" "$APP"
