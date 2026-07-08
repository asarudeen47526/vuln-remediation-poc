#!/usr/bin/env bash
# =============================================================================
# VulnGuard AI — Clean Restart
#
# Forcefully stops everything (even stale/zombie processes), clears pid files,
# and starts fresh.  Use this when start.sh / stop.sh leave the app dead.
#
# Usage:
#   ./restart.sh                # stop + start (keep DB)
#   ./restart.sh --reset-db     # stop + drop/recreate DB + start
#   ./restart.sh --clear-logs   # also wipe all log files before starting
#   ./restart.sh --reset-db --clear-logs
# =============================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ"

PIDS="$PROJ/.pids"
LOGS="$PROJ/logs"

# ── colour helpers ────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[FAIL]\033[0m  $*" >&2; exit 1; }

# ── args ──────────────────────────────────────────────────────────────────────
RESET_DB=0
CLEAR_LOGS=0
for arg in "$@"; do
    case "$arg" in
        --reset-db)    RESET_DB=1 ;;
        --clear-logs)  CLEAR_LOGS=1 ;;
    esac
done

# ── load .env for PORT ────────────────────────────────────────────────────────
if [[ -f "$PROJ/.env" ]]; then
    set -a; source "$PROJ/.env"; set +a
fi
PORT="${PORT:-8080}"

echo ""
echo "============================================================"
echo "  VulnGuard AI — Clean Restart"
echo "  $(date)"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Stop via pid files (graceful)
# ─────────────────────────────────────────────────────────────────────────────
info "Stopping known processes via pid files…"
for name in uvicorn watch_agent r_act p_act; do
    pidfile="$PIDS/${name}.pid"
    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null && ok "Stopped $name (PID $pid)" || true
        else
            warn "$name: pid file exists but process gone — cleaning up"
        fi
        rm -f "$pidfile"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Kill anything still holding the web port (stale uvicorn, etc.)
# ─────────────────────────────────────────────────────────────────────────────
info "Checking port $PORT for stale processes…"
if command -v fuser &>/dev/null; then
    fuser -k "${PORT}/tcp" 2>/dev/null && warn "Killed stale process on port $PORT" || true
elif command -v lsof &>/dev/null; then
    stale_pid=$(lsof -ti tcp:"$PORT" 2>/dev/null | head -1 || true)
    if [[ -n "$stale_pid" ]]; then
        kill "$stale_pid" 2>/dev/null && warn "Killed stale process $stale_pid on port $PORT" || true
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Kill any orphaned python / uvicorn processes for this project
# ─────────────────────────────────────────────────────────────────────────────
info "Looking for orphaned app processes…"
for pattern in "uvicorn app.main" "watch_agent.py" "r_act.py" "p_act.py"; do
    while IFS= read -r pid; do
        kill "$pid" 2>/dev/null && warn "Killed orphan: $pattern (PID $pid)" || true
    done < <(pgrep -f "$pattern" 2>/dev/null || true)
done

# Wait briefly for ports to release
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Clear stale pid files
# ─────────────────────────────────────────────────────────────────────────────
rm -f "$PIDS"/*.pid 2>/dev/null || true
ok "Pid files cleared."

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Optionally clear logs
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$CLEAR_LOGS" == "1" ]]; then
    info "Clearing log files…"
    rm -f "$LOGS"/*.log 2>/dev/null || true
    ok "Logs cleared."
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Start fresh
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "Starting VulnGuard AI…"
echo ""

if [[ "$RESET_DB" == "1" ]]; then
    exec "$PROJ/start.sh" --reset
else
    exec "$PROJ/start.sh"
fi
