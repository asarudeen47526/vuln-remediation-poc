#!/usr/bin/env bash
# =============================================================================
# VulnGuard AI — Control-Node Setup Script
# Run ONCE on the control node (Oracle Linux 8 / RHEL 8 / CentOS Stream 8).
#
# What this does:
#   1. Installs system packages: Python 3.11, Ansible, PostgreSQL
#   2. Initialises PostgreSQL and creates the vulndb database
#   3. Creates a Python virtualenv and installs all Python deps
#   4. Copies .env.example → .env  (if .env does not exist)
#   5. Runs init_db.py to create tables and seed application records
#   6. Generates an SSH keypair for Ansible → target SSH (if not present)
#   7. Installs optional systemd unit files for production use
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
# =============================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ"

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[FAIL]\033[0m  $*" >&2; exit 1; }

echo ""
echo "============================================================"
echo "  VulnGuard AI — Control Node Setup"
echo "  Project: $PROJ"
echo "============================================================"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
info "Installing system packages…"

# Enable EPEL (needed for some Python packages on OL8)
sudo dnf install -y oracle-epel-release-el8 2>/dev/null || \
  sudo dnf install -y epel-release 2>/dev/null || \
  warn "EPEL not available — continuing without it."

sudo dnf install -y \
    git \
    python3-pip \
    postgresql \
    postgresql-server \
    2>/dev/null || true

# Python 3.11 (OL8 ships 3.6 by default; 3.11 is needed for the LLM SDKs)
if ! command -v python3.11 &>/dev/null; then
    info "Installing Python 3.11…"
    sudo dnf install -y python3.11 python3.11-pip || \
        die "python3.11 not available. Install manually: sudo dnf install python3.11"
fi
ok "Python $(python3.11 --version)"

# Ansible
if ! command -v ansible &>/dev/null; then
    info "Installing Ansible…"
    # Try the system package first; fall back to pip install inside venv
    sudo dnf install -y ansible || \
        warn "System ansible not found — will install via pip into the venv."
fi

# ── 2. PostgreSQL ─────────────────────────────────────────────────────────────
info "Setting up PostgreSQL…"

if ! sudo systemctl is-active --quiet postgresql 2>/dev/null; then
    # Initialise the data directory (OL8 requires this before first start)
    if ! sudo postgresql-setup --initdb 2>/dev/null; then
        sudo postgresql-setup initdb 2>/dev/null || true
    fi
    sudo systemctl enable --now postgresql
    sleep 2
fi

# Ensure vulndb exists
DB_NAME="vulndb"
DB_EXISTS=$(sudo -u postgres psql -tc \
    "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | tr -d '[:space:]')
if [[ "$DB_EXISTS" != "1" ]]; then
    sudo -u postgres createdb "$DB_NAME"
    info "Created database '$DB_NAME'."
else
    info "Database '$DB_NAME' already exists."
fi

# Allow the current Unix user to connect to vulndb as postgres
# (pg_hba.conf: local connections from the OS user via peer auth may need a
#  host entry; simplest is to add a pg_hba line for localhost md5 or trust)
PG_HBA=$(sudo -u postgres psql -tc "SHOW hba_file" 2>/dev/null | tr -d '[:space:]')
if [[ -n "$PG_HBA" ]] && ! grep -q "vulndb" "$PG_HBA" 2>/dev/null; then
    echo "host    vulndb          postgres        127.0.0.1/32            md5" \
        | sudo tee -a "$PG_HBA" > /dev/null
    sudo systemctl reload postgresql
    info "Added pg_hba entry for vulndb."
fi

ok "PostgreSQL ready."

# ── 3. Python virtualenv ──────────────────────────────────────────────────────
info "Creating Python 3.11 virtualenv…"
python3.11 -m venv "$PROJ/.venv"
# shellcheck disable=SC1091
source "$PROJ/.venv/bin/activate"

pip install --quiet --upgrade pip
pip install --quiet -r "$PROJ/requirements.txt"

# Install ansible into the venv if the system package is missing
if ! command -v ansible &>/dev/null; then
    pip install --quiet ansible
fi

ok "Python dependencies installed."

# ── 4. .env ───────────────────────────────────────────────────────────────────
if [[ ! -f "$PROJ/.env" ]]; then
    cp "$PROJ/.env.example" "$PROJ/.env"
    warn ".env created from .env.example"
    warn "EDIT IT NOW before running start.sh:"
    warn "  vi $PROJ/.env"
    warn ""
    warn "Key values to set for the control node:"
    warn "  LLM_PROVIDER=anthropic  (or claude-sdk / openai / gemini)"
    warn "  ANTHROPIC_API_KEY=sk-ant-..."
    warn "  TARGET_HOST=<target private IP>"
    warn "  SSH_USER=aiagent"
    warn "  SSH_KEY=~/.ssh/id_rsa"
    warn "  DRY_RUN=0               (1 for local dev without a real target)"
else
    ok ".env already exists."
fi

# ── 5. Database init ──────────────────────────────────────────────────────────
info "Initialising database tables…"
if [[ -f "$PROJ/.env" ]]; then
    set -a; source "$PROJ/.env"; set +a
fi
python "$PROJ/init_db.py" && ok "Database initialised."

# ── 6. SSH keypair ────────────────────────────────────────────────────────────
SSH_KEY_PATH="${SSH_KEY:-$HOME/.ssh/id_rsa}"
SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"
if [[ ! -f "$SSH_KEY_PATH" ]]; then
    info "Generating SSH keypair at $SSH_KEY_PATH…"
    mkdir -p "$(dirname "$SSH_KEY_PATH")"
    ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_PATH" -N "" -C "vulnguard-control-node"
    ok "SSH keypair created."
    echo ""
    warn "Copy this public key to the target node:"
    warn "  ssh-copy-id -i ${SSH_KEY_PATH}.pub ${SSH_USER:-aiagent}@\${TARGET_HOST}"
    warn "Or manually append to /home/aiagent/.ssh/authorized_keys on the target."
    echo ""
    cat "${SSH_KEY_PATH}.pub"
    echo ""
else
    ok "SSH key already exists at $SSH_KEY_PATH."
fi

# ── 7. Logs directory ─────────────────────────────────────────────────────────
mkdir -p "$PROJ/logs" "$PROJ/.pids" "$PROJ/reports"
ok "Directories: logs/, .pids/, reports/"

# ── 8. Optional: systemd unit files ──────────────────────────────────────────
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-}"
if [[ -z "$INSTALL_SYSTEMD" ]]; then
    read -rp "Install systemd service units for production auto-start? [y/N] " INSTALL_SYSTEMD
fi

if [[ "${INSTALL_SYSTEMD,,}" == "y" ]]; then
    VENV_PYTHON="$PROJ/.venv/bin/python"
    USER="$(whoami)"

    sudo tee /etc/systemd/system/vulnguard-web.service > /dev/null << EOF
[Unit]
Description=VulnGuard AI — Web Dashboard
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${PROJ}
EnvironmentFile=${PROJ}/.env
ExecStart=${VENV_PYTHON} -m uvicorn app.main:app --host 0.0.0.0 --port \${PORT:-8080}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/vulnguard-watch.service > /dev/null << EOF
[Unit]
Description=VulnGuard AI — Watch Agent (UI pipeline)
After=network-online.target vulnguard-web.service
Wants=network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${PROJ}
EnvironmentFile=${PROJ}/.env
ExecStart=${VENV_PYTHON} ${PROJ}/watch_agent.py
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable vulnguard-web.service vulnguard-watch.service
    ok "Systemd units installed and enabled."
    info "To start: sudo systemctl start vulnguard-web vulnguard-watch"
    info "To view logs: journalctl -fu vulnguard-web"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Setup complete!"
echo "============================================================"
echo ""
echo "Next steps:"
echo ""
echo "  1. Edit .env (if you haven't already):"
echo "       vi $PROJ/.env"
echo ""
echo "  2. Verify connectivity:"
echo "       source $PROJ/.venv/bin/activate"
echo "       python selftest.py"
echo ""
echo "  3. Start VulnGuard:"
echo "       ./start.sh"
echo ""
echo "  4. Open the dashboard:"
echo "       http://\$(hostname -I | awk '{print \$1}'):8080"
echo ""
