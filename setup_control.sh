#!/usr/bin/env bash
# Run this ON THE CONTROL NODE (Oracle Linux 8, A1/6GB).
# Installs the brain + executor: Python 3.11 venv, LLM SDKs, Ansible.
# The control node holds the LLM API key and the SSH key to the target.
set -euo pipefail

sudo dnf install -y git python3-pip
sudo dnf config-manager --enable ol8_developer_EPEL || true
sudo dnf install -y ansible

# OL8's default python3 is 3.6 - too old for the LLM SDKs. Install 3.11.
if ! command -v python3.11 >/dev/null 2>&1; then
  sudo dnf install -y python3.11 python3.11-pip
fi

python3.11 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install ansible

echo
echo "============================================================"
echo " Control node ready.  Next steps:"
echo "============================================================"
echo ""
echo "1. Edit .env:"
echo "   cp .env .env.bak   # keep a backup"
echo "   vi .env"
echo "   -- set LLM_PROVIDER + matching API key"
echo "   -- set TARGET_HOST=<target private IP>"
echo "   -- set SSH_USER=aiagent"
echo "   -- set SSH_KEY=~/.ssh/id_rsa  (or your key path)"
echo "   -- set DRY_RUN=0              (enable real patching)"
echo "   -- set REMOTE_REPORT_PATH=/tmp/trivy_scan.json"
echo "   -- set TRIVY_PATH=/usr/local/bin/trivy"
echo ""
echo "2. Load the environment:"
echo "   set -a; source .env; set +a"
echo ""
echo "3. Verify all links work:"
echo "   # LLM reachable"
echo "   python -c \"from llm_client import generate; print(generate('one word','ready'))\""
echo "   # SSH to target works"
echo "   ssh -i \$SSH_KEY \$SSH_USER@\$TARGET_HOST 'echo SSH OK'"
echo "   # Ansible can reach target"
echo "   ansible -i \$TARGET_HOST, all -u \$SSH_USER --private-key \$SSH_KEY -m ping"
echo ""
echo "4. Run analysis first (read-only, safe):"
echo "   python analyze.py"
echo ""
echo "5. Then run the agents:"
echo "   python p_act.py          # proactive: scans on schedule, asks approval"
echo "   python r_act.py          # reactive: polls target for Trivy report"
echo ""
echo "Tip: on the target, set up a cron job to run Trivy and write to REMOTE_REPORT_PATH:"
echo "  # on target-node01, as root:"
echo "  echo '0 * * * * /usr/local/bin/trivy rootfs --scanners vuln --pkg-types os'"
echo "       "--severity HIGH,CRITICAL --quiet --format json -o /tmp/trivy_scan.json /' \\"
echo "  | crontab -"
