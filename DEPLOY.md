# Deployment Guide

Two-node topology:

```
[ Control Node ]  ---SSH/SCP/Ansible--->  [ target-node01 ]
  agents + LLM                              Trivy + nginx
  API key + SSH key                         no secrets, no agents
```

---

## 1. Target Node  (172.16.0.9)

Run all commands in this section **as root** on the target.

### 1a. Create the agent user

```bash
useradd -m -s /bin/bash aiagent

# Scope sudo to only what the Ansible playbook needs
cat > /etc/sudoers.d/aiagent << 'EOF'
aiagent ALL=(ALL) NOPASSWD: /usr/bin/dnf, /usr/bin/systemctl, /usr/sbin/dnf
EOF
chmod 440 /etc/sudoers.d/aiagent

# Smoke-test the sudoers rule
sudo -u aiagent sudo -n dnf --version
```

### 1b. Authorise the control-node SSH key

On the control node, generate the key first (step 2a below).
Then paste its public half here:

```bash
mkdir -p /home/aiagent/.ssh
# paste the output of `cat ~/.ssh/id_rsa.pub` from the control node:
echo "ssh-rsa AAAA..." >> /home/aiagent/.ssh/authorized_keys
chmod 700 /home/aiagent/.ssh
chmod 600 /home/aiagent/.ssh/authorized_keys
chown -R aiagent:aiagent /home/aiagent/.ssh
```

### 1c. Install Trivy

```bash
cat > /etc/yum.repos.d/trivy.repo << 'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF

dnf install -y trivy
trivy --version          # should print: Trivy 0.5x.x
```

### 1d. Add nginx health endpoint

The Ansible playbook smoke-tests `http://localhost/health` after every patch.
Add this inside your `server {}` block in `/etc/nginx/nginx.conf`:

```nginx
location /health {
    access_log off;
    return 200 "ok\n";
    add_header Content-Type text/plain;
}
```

```bash
nginx -t && systemctl reload nginx
curl -s http://localhost/health   # must print: ok
```

### 1e. Set up the hourly Trivy cron job

R-Act polls this file. It must be readable by `aiagent`.

```bash
cat > /etc/cron.d/trivy-scan << 'EOF'
0 * * * * root /usr/local/bin/trivy rootfs --scanners vuln --pkg-types os \
  --severity HIGH,CRITICAL --timeout 15m --quiet --format json \
  -o /tmp/trivy_scan.json / && chmod 644 /tmp/trivy_scan.json
EOF

# Run once now to produce the initial report (takes a few minutes)
/usr/local/bin/trivy rootfs --scanners vuln --pkg-types os \
  --severity HIGH,CRITICAL --timeout 15m --quiet --format json \
  -o /tmp/trivy_scan.json /
chmod 644 /tmp/trivy_scan.json

# Verify aiagent can read it
sudo -u aiagent python3 -c "
import json
d = json.load(open('/tmp/trivy_scan.json'))
print('Results count:', len(d.get('Results', [])))
"
```

---

## 2. Control Node

Run all commands in this section as **your normal user** on the control node.

### 2a. Generate the SSH key pair

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
cat ~/.ssh/id_rsa.pub
# Copy this entire line into /home/aiagent/.ssh/authorized_keys on the target (step 1b)
```

### 2b. Get the project onto the control node

```bash
# Option A: git clone
git clone <your-repo-url> ~/vuln-remediation-poc

# Option B: scp from your laptop
scp -r /path/to/vuln-remediation-poc <user>@<control-node-ip>:~/vuln-remediation-poc
```

### 2c. Install system dependencies

```bash
sudo dnf install -y git python3.11 python3.11-pip ansible

python3.11 --version   # Python 3.11.x
ansible --version      # core 2.x
```

### 2d. Create the Python virtual environment

```bash
cd ~/vuln-remediation-poc
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2e. Configure .env

```bash
cp .env .env.bak    # keep original as backup
vi .env
```

Set these values; leave everything else as-is:

```bash
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...        # your real Anthropic API key

TARGET_HOST=172.16.0.9
SSH_USER=aiagent
SSH_KEY=~/.ssh/id_rsa

HEALTH_URL=http://localhost/health  # nginx health endpoint on the target

DRY_RUN=0                           # IMPORTANT: 0 = real patching

TRIVY_PATH=/usr/local/bin/trivy
REMOTE_REPORT_PATH=/tmp/trivy_scan.json

WATCH_INTERVAL=30                   # R-Act: poll target every 30 seconds
SCAN_INTERVAL=3600                  # P-Act: trigger full scan every hour
```

Load into current shell:

```bash
set -a; source .env; set +a
```

---

## 3. Verify All Links

Run every check below. All must pass before running agents.

```bash
source .venv/bin/activate
set -a; source .env; set +a

# 3a. SSH to target as aiagent
ssh -i ~/.ssh/id_rsa aiagent@172.16.0.9 "echo SSH OK && hostname"

# 3b. Ansible ping
ansible -i 172.16.0.9, all -u aiagent --private-key ~/.ssh/id_rsa -m ping

# 3c. Ansible can escalate to root (needed for dnf patching)
ansible -i 172.16.0.9, all -u aiagent --private-key ~/.ssh/id_rsa \
  -m command -a "dnf --version" --become

# 3d. LLM is reachable and returns a response
python -c "from llm_client import generate; print(generate('Reply with: ready', 'ping'))"

# 3e. Full local smoke test (config + LLM + safety gate)
python selftest.py

# 3f. SCP pull of the Trivy report works
scp -i ~/.ssh/id_rsa aiagent@172.16.0.9:/tmp/trivy_scan.json /tmp/test_pull.json \
  && python -c "
import json
d = json.load(open('/tmp/test_pull.json'))
vulns = sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results', []))
print(f'SCP pull OK -- {vulns} vulnerabilities in report')
"
```

All six checks green? You're ready.

---

## 4. Run Analysis (Read-Only — Always Safe)

`analyze.py` produces a report and exits. It never patches anything.
Run this first to understand what the target looks like before agents touch it.

```bash
source .venv/bin/activate
set -a; source .env; set +a

python analyze.py
# Pulls /tmp/trivy_scan.json from target via SCP
# SSHs to target to gather: OS, running services, open ports, app versions,
#   processes with libcurl/libssl loaded in memory
# Calls LLM for full risk + impact analysis
# Writes: reports/vuln_analysis_<timestamp>.md
```

Review `reports/vuln_analysis_*.md` before proceeding.

---

## 5. Run the Agents

Each is a long-running loop. Use `tmux` or `screen` to keep them alive, or
use the systemd unit files in step 6.

### R-Act — reactive (recommended starting point)

R-Act waits for a new Trivy report and acts on it immediately.

```bash
source .venv/bin/activate
set -a; source .env; set +a
python r_act.py
```

What happens:
1. Every 30 s: SCP `/tmp/trivy_scan.json` from target
2. If the file has a newer mtime: gather server context (read-only SSH)
3. For each new HIGH/CRITICAL CVE: print the approval screen (see section 7 below)
4. On `y`: run `playbooks/patch.yml` via Ansible
5. Ansible: patches package → restarts affected services → smoke tests health URL
6. On smoke-test failure: Ansible automatically rolls back via `dnf history undo last` and restarts services again
7. Every decision (approved/skipped/rolled back) is appended to `audit.log`

### P-Act — proactive (runs its own scans on schedule)

```bash
source .venv/bin/activate
set -a; source .env; set +a
python p_act.py
```

What happens: every 3600 s, SSHes to target and runs Trivy directly, then the
same pipeline as R-Act. Use this when you want the agents to drive the cadence
rather than relying on the target's cron job.

---

## 6. Run as systemd Services (Production)

Replace `$USER` and `$HOME` with your actual values, or run the heredoc as
the target user so the shell expands them.

```bash
# R-Act
sudo tee /etc/systemd/system/r-act.service > /dev/null << EOF
[Unit]
Description=Vulnerability Remediation R-Act Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/vuln-remediation-poc
EnvironmentFile=$HOME/vuln-remediation-poc/.env
ExecStart=$HOME/vuln-remediation-poc/.venv/bin/python r_act.py
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# P-Act (same structure, different script)
sudo tee /etc/systemd/system/p-act.service > /dev/null << EOF
[Unit]
Description=Vulnerability Remediation P-Act Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/vuln-remediation-poc
EnvironmentFile=$HOME/vuln-remediation-poc/.env
ExecStart=$HOME/vuln-remediation-poc/.venv/bin/python p_act.py
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now r-act.service
sudo systemctl enable --now p-act.service

# Watch live logs
journalctl -fu r-act.service
journalctl -fu p-act.service
```

> **Note**: when running as a systemd service the approval prompt (`[y/N]`) does
> not reach a terminal. For unattended operation you would need to add an
> auto-approve mode or a webhook notification. For now, run the agents directly
> in a terminal so you can respond to prompts.

---

## 7. Approval Screen

When a new CVE is found you will see this before anything is patched:

```
=== [R-Act] CVE-2023-38545 in curl (CRITICAL) ===

  ╔══════════════════════════════════════════════════════════╗
  ║                   REMEDIATION PLAN                      ║
  ╚══════════════════════════════════════════════════════════╝
  CVE      : CVE-2023-38545  [CRITICAL]
  Action   : update_package
  Package  : curl
  Current  : 7.76.1-14.el8_8.2
  Target   : 7.76.1-26.el8
  Restart  : nginx
  Reboot   : no
  Reason   : curl is linked by nginx at runtime; this CVE is a heap buffer
             overflow in the SOCKS5 proxy handshake exploitable remotely

  ╔══════════════════════════════════════════════════════════╗
  ║         RESTORATION PLAN  (auto if smoke test fails)    ║
  ╚══════════════════════════════════════════════════════════╝
  If smoke test fails: dnf history undo last restores curl to
  7.76.1-14.el8_8.2 and nginx is restarted to reload the original
  library. No manual action required.

  Approve remediation from R-Act? [y/N]
```

- `y` + Enter → patch runs, services restart, smoke test fires, auto-rollback on failure
- `N` or just Enter → logged as `skipped`, agent moves on

---

## 8. Monitoring

| What | Where |
|---|---|
| Every patching decision | `audit.log` in the project directory |
| Analysis reports | `reports/vuln_analysis_*.md` |
| Agent logs (systemd) | `journalctl -fu r-act.service` |
| Trivy raw scan | `/tmp/trivy_scan.json` on the target |

```bash
# Pretty-print the last 5 audit entries
tail -5 audit.log | python -c "
import sys, json
for line in sys.stdin:
    print(json.dumps(json.loads(line), indent=2))
"
```

---

## 9. Manual Rollback Reference

The playbook rolls back automatically on smoke-test failure. If you ever need to
roll back manually on the target:

```bash
# On target-node01 as root
dnf history list
dnf history undo <transaction-id>
systemctl restart nginx    # or whichever service was restarted
```

---

## Golden Rules

| Rule | Why |
|---|---|
| `DRY_RUN=1` on your laptop | Safe — prints Ansible command instead of running it |
| `DRY_RUN=0` on the control node | Real patching |
| Never commit `.env` | Contains API key + SSH key path |
| Never put agent code or API keys on the target | Target is untrusted surface |
| Run `analyze.py` before agents | Understand the risk posture first |
