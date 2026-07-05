# Vulnerability Remediation Agents — R-Act & P-Act (POC)

A cost-free proof of concept: two AI agents that identify vulnerabilities on a
Linux server and remediate them **with user approval**, using a Claude, GPT, or
Gemini API key. Two VMs, an open-source scanner, and a fixed Ansible playbook.

---

## 1. The approach in one picture

```
                       ┌─────────────────────────────────────────┐
                       │            CONTROL NODE (VM 1)            │
                       │                                           │
 vuln report ─────────▶│  R-Act  ┐                                │
 (external tool)       │         ├─▶ remediation_core ─▶ LLM API ──┼──▶ Claude / GPT / Gemini
 schedule ────────────▶│  P-Act  ┘        │  (plan)               │        (returns a plan)
                       │                  │ validate + approve    │
                       │                  ▼                       │
                       │            ansible-playbook ── SSH ───────┼──▶  TARGET (VM 2)
                       └─────────────────────────────────────────┘       RHEL/Oracle Linux 8
                                                                          Trivy + nginx + sudo
```

**R-Act (reactive)** and **P-Act (proactive)** share the *exact same* remediation
core, safety gate, approval prompt, playbook, and rollback. The only difference
is the trigger:

| | R-Act | P-Act |
|---|---|---|
| Trigger | An external tool reports a finding | Its own schedule |
| Behaviour | Reacts the moment a report lands | Initiates scans to find issues early |
| Code | `r_act.py` | `p_act.py` |
| Everything else | `remediation_core.py` + `playbooks/patch.yml` (identical) | same |

Your NPT / pentest findings feed R-Act the same way a scanner report does — as
normalized findings the core consumes.

### Safety model (holds for both agents)
1. The LLM only ever produces a **plan** (JSON). It never runs a command.
2. Every plan passes a **hard gate** — JSON schema + an allow-list of actions
   (`update_package`, `downgrade_package`) + the package must match the finding.
3. Nothing runs without a **human `y`** at the approval prompt.
4. Execution is a **fixed, reviewed playbook** — the model cannot inject tasks.
5. A failed **smoke test auto-rolls-back** the change.
6. Every decision + outcome is written to `audit.log`.

---

## 2. What you need

- A laptop with SSH.
- **One** LLM API key: Anthropic *or* OpenAI *or* Google (Gemini).
- A cloud account for two small VMs. Recommended: **Oracle Cloud Always Free**
  (genuinely $0, no expiry). AWS/Azure free trials also work but expire.

---

## 3. Phase 1 — Create the two VMs (Oracle Cloud Always Free)

1. Sign up at oracle.com/cloud/free. Choose a **home region** with multiple
   availability domains (e.g. US East Ashburn, UK South London) for better ARM
   capacity. Free resources are locked to this region.
2. Console → Compute → Instances → **Create instance**, twice. The free Ampere
   A1 allowance (2 OCPU / 12 GB) splits nicely into two VMs:
   - **control** — Image: Ubuntu 22.04. Shape: Ampere A1 Flex, 1 OCPU / 6 GB.
   - **target** — Image: **Oracle Linux 8** (RHEL-compatible, `dnf` identical, no
     subscription needed). Shape: Ampere A1 Flex, 1 OCPU / 6 GB.
3. Put both in the **same VCN/subnet**. Paste your SSH public key for each.
4. Subnet **security list** ingress rules:
   - SSH (22) from *your IP* → control
   - SSH (22) and HTTP (80) from *control's private IP* → target
5. If you hit “Out of capacity”, try another availability domain or upgrade to
   Pay-As-You-Go (Always Free resources stay free; you just get priority hardware).

> On other clouds: launch two small burstable instances (control = Ubuntu,
> target = RHEL/Rocky/Oracle Linux 8), same security-group rules, and **stop them
> when idle**. The rest of this guide is identical.

---

## 4. Phase 2 — Prepare the TARGET (Oracle Linux 8)

SSH into the target, then:

```bash
# Sample app the smoke test will check
sudo dnf install -y nginx
echo ok | sudo tee /usr/share/nginx/html/health
sudo systemctl enable --now nginx

# Trivy — free open-source vulnerability scanner (ARM build works on A1)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin

# Service account the agents log in as (never root)
sudo useradd -m patch-agent
sudo mkdir -p /home/patch-agent/.ssh && sudo chmod 700 /home/patch-agent/.ssh

# POC sudo rights. Ansible's become needs to run its module runner via sudo, so
# for an ISOLATED lab VM we grant passwordless sudo. In production, scope this to
# specific binaries — the real guardrail is the agent's allow-list + fixed
# playbook, not this file.
echo 'patch-agent ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/patch-agent
```

**Do not fully patch the box** — leaving it behind on updates is what gives the
agents real HIGH/CRITICAL findings to remediate. Confirm material exists:

```bash
dnf updateinfo list security      # built-in cross-check: CVE-mapped advisories
```

---

## 5. Phase 3 — Prepare the CONTROL node + SSH trust

On the control VM:

```bash
sudo apt update && sudo apt install -y python3-pip ansible git
git clone <this-repo> vuln-remediation-poc && cd vuln-remediation-poc
pip3 install -r requirements.txt

# Key the agents will use to reach the target
ssh-keygen -t ed25519 -f ~/.ssh/id_patch -N ""
cat ~/.ssh/id_patch.pub        # copy this line
```

Add that public key to the target's `patch-agent` account (run on the **target**):

```bash
echo 'PASTE_THE_PUBKEY_HERE' | sudo tee -a /home/patch-agent/.ssh/authorized_keys
sudo chown -R patch-agent: /home/patch-agent/.ssh
sudo chmod 600 /home/patch-agent/.ssh/authorized_keys
```

Verify the whole Linux path from the control node (use the target's private IP):

```bash
ssh -i ~/.ssh/id_patch patch-agent@<target-private-ip> "sudo dnf --version"
```

---

## 6. Phase 4 — Configure and connect the LLM

```bash
cp .env.example .env
# edit .env: pick LLM_PROVIDER, paste the matching key, set TARGET_HOST/SSH_KEY
set -a; source .env; set +a
```

Smoke-test the model connection:

```bash
python3 -c "from llm_client import generate; print(generate('Reply with one word.', 'ready'))"
```

Switching providers later is just editing `LLM_PROVIDER` (and the key) in `.env` —
no code changes. Model ids move fast; if a default is stale, set `LLM_MODEL`.

---

## 7. Phase 5 — Run the POC

### Demo P-Act (proactive)
It scans the target itself, then for each HIGH/CRITICAL finding prints a plan and
waits for your approval:

```bash
python3 p_act.py
```

### Demo R-Act (reactive)
Start it watching, then simulate the vuln tool "reporting" by generating a scan
report and dropping it where R-Act looks — it reacts instantly:

```bash
python3 r_act.py &                       # start the watcher
mkdir -p ~/incoming
ssh -i ~/.ssh/id_patch patch-agent@<target-private-ip> \
  "sudo trivy rootfs --scanners vuln --severity HIGH,CRITICAL --quiet --format json /" \
  > ~/incoming/scan.json                 # the moment this lands, R-Act acts
```

In both cases you'll see: **finding → LLM plan → validation → your `y` →
playbook patches → smoke test → result logged to `audit.log`.** Re-run the scan
afterward and the fixed CVEs are gone — the closed loop.

Force a failure to see rollback: point `HEALTH_URL` at a bad path in `.env` and
re-run — the smoke test fails and the change is automatically reverted.

---

## 8. Files

| File | Role |
|---|---|
| `config.py` | All settings, from env vars |
| `llm_client.py` | Provider adapter — Claude / GPT / Gemini behind one `generate()` |
| `remediation_core.py` | Normalize, plan, validate, approve, execute, audit (shared) |
| `r_act.py` | Reactive agent (watches for reports) |
| `p_act.py` | Proactive agent (scans on a schedule) |
| `playbooks/patch.yml` | Fixed playbook: patch + smoke test + auto-rollback |
| `.env.example` | Copy to `.env` |

---

## 9. Where to take it next (Phase 6+)

- Add the human-approval gate as a **ticket** (ServiceNow/Jira) instead of a CLI
  `y`, so approvals are auditable and role-based.
- Enrich findings with **CISA KEV + EPSS** in P-Act's `scan()` to prioritize by
  real-world exploitability.
- Move SSH keys into **HashiCorp Vault** (short-lived certs) and take a **VM
  snapshot** before patching for heavier rollback.
- Add the **Windows path**: same core, swap SSH→WinRM and the `dnf` task for
  `ansible.windows.win_updates`.
- Persist `audit.log` to a database and put **Grafana** on top.

> Notes: model ids and cloud free-tier limits change over time — verify current
> values with each provider before a long run. Keep the target VM's `sudo` rights
> scoped down for anything beyond an isolated lab.
