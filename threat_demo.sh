#!/usr/bin/env bash
# lab only: sends a real port scan and syn flood to this machine's own address.
# for a safe demo without any traffic use simulation mode: ENABLE_SIMULATION_MODE=1 ./run.sh
set -euo pipefail

if [ "${I_OWN_THIS_NETWORK:-}" != "yes" ]; then
    echo "refusing to run: this sends real scan and flood traffic. set I_OWN_THIS_NETWORK=yes to confirm" >&2
    exit 1
fi

TARGET=$(hostname -I | awk '{print $1}')
echo "target: $TARGET (this host)"

echo "[1/2] port scan"
sudo nmap -p 80,443,22,3306,5432,8080,9000,27017,6379,5000 "$TARGET" >/dev/null 2>&1 || echo "nmap failed or is not installed"
sleep 3

echo "[2/2] syn flood for 5 seconds"
sudo timeout 5 hping3 -S -p 5000 -i u100 -c 2000 "$TARGET" >/dev/null 2>&1 || echo "hping3 failed or is not installed"

echo "done, open http://localhost:5000"
