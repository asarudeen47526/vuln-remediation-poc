#!/usr/bin/env bash
# =============================================================================
# VulnGuard AI — Start Script
# Starts the full platform: web dashboard + watch agent.
# Optionally also starts r_act / p_act for interactive terminal remediation.
#
# Usage:
#   ./start.sh              # start dashboard + watch agent
#   ./start.sh --with-agents # also start r_act and p_act in background
#   ./start.sh --reset      # wipe the DB and re-seed before starting
#
# Prerequisites: run ./setup.sh once first.
# =============================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ"

PIDS="$PROJ/.pids"
LOGS="$PROJ/logs"
mkdir -p "$PIDS" "$LOGS" "$PROJ/reports"

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[FAIL]\033[0m  $*" >&2; exit 1; }

is_running() {
    local pidfile="$PIDS/$1.pid"
    [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

start_proc() {
    local name="$1"; shift
    local pidfile="$PIDS/${name}.pid"
    if is_running "$name"; then
        ok "$name already running (PID $(cat "$pidfile"))"
        return
    fi
    nohup "$@" >> "$LOGS/${name}.log" 2>&1 &
    echo $! > "$pidfile"
    ok "$name started (PID $!) → logs/${name}.log"
}

# ── parse args ────────────────────────────────────────────────────────────────
WITH_AGENTS=0
RESET=0
for arg in "$@"; do
    case "$arg" in
        --with-agents) WITH_AGENTS=1 ;;
        --reset)       RESET=1 ;;
    esac
done

# ── load .env ─────────────────────────────────────────────────────────────────
if [[ ! -f "$PROJ/.env" ]]; then
    die ".env not found. Run ./setup.sh first."
fi
set -a; source "$PROJ/.env"; set +a

VENV_PYTHON="$PROJ/.venv/bin/python"
if [[ ! -f "$VENV_PYTHON" ]]; then
    die "Virtualenv not found at $PROJ/.venv. Run ./setup.sh first."
fi

PORT="${PORT:-8080}"
DRY_RUN="${DRY_RUN:-1}"
AIT_ID="${AIT_ID:-AIT-001}"

echo ""
echo "============================================================"
if [[ "$DRY_RUN" == "1" ]]; then
    echo "  VulnGuard AI — Starting  [DRY_RUN mode]"
else
    echo "  VulnGuard AI — Starting  [LIVE mode — real patching]"
fi
echo "  Project: $PROJ"
echo "  Dashboard: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost):$PORT"
echo "============================================================"
echo ""

# ── 1. PostgreSQL ─────────────────────────────────────────────────────────────
info "Checking PostgreSQL…"

# ---- find service name (varies by distro / module stream) -------------------
PG_SERVICE=""
for _svc in postgresql postgresql-server postgresql-15 postgresql-14 postgresql-13; do
    if sudo systemctl list-unit-files "${_svc}.service" 2>/dev/null | grep -q "${_svc}.service"; then
        PG_SERVICE="$_svc"
        break
    fi
done

# ---- install + init if missing ----------------------------------------------
if [[ -z "$PG_SERVICE" ]]; then
    info "postgresql-server not found — installing…"
    sudo dnf install -y postgresql-server || die "dnf install postgresql-server failed."
    PG_SERVICE="postgresql"
fi

# ---- initialise data directory if needed ------------------------------------
if ! sudo -u postgres test -f "/var/lib/pgsql/data/PG_VERSION" 2>/dev/null; then
    info "Initialising PostgreSQL data directory…"
    sudo postgresql-setup --initdb || sudo postgresql-setup initdb || \
        die "postgresql-setup --initdb failed."
fi

# ---- start the service ------------------------------------------------------
if ! sudo systemctl is-active --quiet "$PG_SERVICE" 2>/dev/null; then
    sudo systemctl enable "$PG_SERVICE" 2>/dev/null || true
    sudo systemctl start  "$PG_SERVICE" || die "Cannot start $PG_SERVICE."
    sleep 3
fi

# ---- ensure pg_hba allows password auth from localhost ----------------------
PG_HBA=$(sudo -u postgres psql -Atc "SHOW hba_file" 2>/dev/null || true)
if [[ -n "$PG_HBA" ]] && ! grep -q "127.0.0.1.*md5\|127.0.0.1.*scram\|localhost.*md5\|localhost.*scram" "$PG_HBA" 2>/dev/null; then
    # Prepend a host entry so the Python app can connect with a password
    TMP=$(mktemp)
    { echo "host    all             postgres        127.0.0.1/32            md5"
      cat "$PG_HBA"; } > "$TMP"
    sudo cp "$TMP" "$PG_HBA"; rm -f "$TMP"
    sudo systemctl reload "$PG_SERVICE"
    info "Updated pg_hba.conf for local password auth."
fi

# ---- set postgres OS password to match DATABASE_URL -------------------------
PG_PASS="${DATABASE_URL:-}"
PG_PASS="${PG_PASS##*:}"          # strip up to last colon (gets "password@host/db")
PG_PASS="${PG_PASS%%@*}"          # strip from @ onwards  (gets "password")
PG_PASS="${PG_PASS:-postgres}"
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '${PG_PASS}';" 2>/dev/null || true

# ---- create the database if needed ------------------------------------------
DB_NAME="${DATABASE_URL:-postgresql://postgres:postgres@localhost:5432/vulndb}"
DB_NAME="${DB_NAME##*/}"          # last path component
DB_EXISTS=$(sudo -u postgres psql -Atc \
    "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null || true)
if [[ "$DB_EXISTS" != "1" ]]; then
    sudo -u postgres createdb "$DB_NAME"
    info "Created database '$DB_NAME'."
fi

# ---- final readiness check --------------------------------------------------
if command -v pg_isready &>/dev/null; then
    pg_isready -q 2>/dev/null || die "PostgreSQL not ready after start."
fi
ok "PostgreSQL is ready ($PG_SERVICE)."

# ── 2. Database init ──────────────────────────────────────────────────────────
if [[ "$RESET" == "1" ]]; then
    warn "--reset: dropping and recreating all tables + data…"
    "$VENV_PYTHON" "$PROJ/init_db.py" --reset
else
    info "Ensuring database tables and seed data exist…"
    "$VENV_PYTHON" "$PROJ/init_db.py"
fi
ok "Database ready."

# ── 3. Web dashboard (uvicorn) ────────────────────────────────────────────────
info "Starting web dashboard on port $PORT…"
start_proc uvicorn \
    "$VENV_PYTHON" -m uvicorn app.main:app \
    --host 0.0.0.0 --port "$PORT" --reload

# Give uvicorn a moment to bind before the watch agent tries to talk to it
sleep 2

# ── 4. Watch agent ────────────────────────────────────────────────────────────
info "Starting watch agent (report → analyze → UI publish)…"
start_proc watch_agent \
    "$VENV_PYTHON" "$PROJ/watch_agent.py"

# ── 5. Optional: R-Act / P-Act agents (interactive terminal flow) ─────────────
if [[ "$WITH_AGENTS" == "1" ]]; then
    echo ""
    warn "NOTE: R-Act and P-Act require a terminal for the human approval prompt."
    warn "      Running them in background means approval prompts go to the log."
    warn "      For interactive use, run them manually in separate terminals:"
    warn "        source .venv/bin/activate && python r_act.py"
    warn "        source .venv/bin/activate && python p_act.py"
    echo ""

    info "Starting R-Act (reactive — polls target for Trivy report)…"
    start_proc r_act \
        "$VENV_PYTHON" "$PROJ/r_act.py"

    info "Starting P-Act (proactive — runs its own Trivy scans on schedule)…"
    start_proc p_act \
        "$VENV_PYTHON" "$PROJ/p_act.py"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  VulnGuard AI is running"
echo "============================================================"
echo ""
echo "  Dashboard   : http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost):$PORT"
echo "  AIT in use  : $AIT_ID"
echo "  Mode        : $([ "$DRY_RUN" = "1" ] && echo "DRY_RUN (safe)" || echo "LIVE (real patching)")"
echo ""
echo "  Logs:"
echo "    tail -f $LOGS/uvicorn.log"
echo "    tail -f $LOGS/watch_agent.log"
echo ""
echo "  What to expect:"
if [[ "$DRY_RUN" == "1" ]]; then
    echo "    1. The watch agent checks if LLM analysis is missing"
    echo "    2. It calls the LLM and stores per-CVE analysis in the DB"
    echo "    3. Open the dashboard → select AIT-001 → see findings + analysis"
    echo "    4. Each finding has a ready remediation plan → click 'Agent Remediate'"
else
    echo "    1. The watch agent polls $TARGET_HOST every ${WATCH_INTERVAL}s"
    echo "    2. On new Trivy report: imports findings, generates plans, runs analysis"
    echo "    3. Open the dashboard → see live findings + analysis as they arrive"
    echo "    4. Click 'Agent Remediate' on any finding with a validated plan"
    echo "    5. For interactive approval: run r_act.py or p_act.py in a terminal"
fi
echo ""
echo "  Stop all:     ./stop.sh"
if [[ "$WITH_AGENTS" != "1" ]]; then
    echo "  With agents:  ./stop.sh && ./start.sh --with-agents"
fi
echo ""
