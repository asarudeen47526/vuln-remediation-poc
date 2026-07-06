#!/usr/bin/env bash
# =============================================================================
# VulnGuard AI — Stop Script
# Gracefully stops all VulnGuard processes started by start.sh.
# =============================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDS="$PROJ/.pids"

ok()   { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m  $*"; }

echo ""
echo "============================================================"
echo "  VulnGuard AI — Stopping"
echo "============================================================"
echo ""

STOPPED=0

for name in uvicorn watch_agent r_act p_act; do
    pidfile="$PIDS/${name}.pid"
    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null && ok "Stopped $name (PID $pid)" || \
                warn "Could not stop $name (PID $pid) — may have already exited."
            STOPPED=$((STOPPED + 1))
        else
            warn "$name PID file exists but process ($pid) is not running."
        fi
        rm -f "$pidfile"
    fi
done

if [[ $STOPPED -eq 0 ]]; then
    warn "No running VulnGuard processes found."
else
    echo ""
    ok "Stopped $STOPPED process(es)."
fi

echo ""
echo "To start again:  ./start.sh"
echo ""
