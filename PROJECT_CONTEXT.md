# PROJECT_CONTEXT.md — read this first

Design context for anyone (human or AI assistant) working on this repo. If you
are an AI assistant in VS Code, treat this as authoritative for how the system
is meant to work.

## Goal
A proof-of-concept for AI-driven Linux vulnerability remediation with a human in
the loop. It identifies vulnerabilities on a target server and remediates them
**only after user approval**.

## Three agents
- **R-Act** (`r_act.py`) — REACTIVE. Watches for a scan report to appear
  (`REPORT_PATH`) and acts on new HIGH/CRITICAL findings as they arrive.
- **P-Act** (`p_act.py`) — PROACTIVE. Runs its own scans on a schedule
  (`SCAN_INTERVAL`) to find issues early.
- **Analysis** (`analyze.py`) — READ-ONLY. Sends all findings to the LLM and
  writes a prioritized markdown analysis report to `reports/`. Never remediates.

R-Act and P-Act share the SAME remediation core and safety gate; only the
trigger differs. Do not duplicate remediation logic into the agents.

## Topology (two VMs, Oracle Linux 8, OCI Ampere A1 / 6 GB each)
- **control-node** — runs all agents, `remediation_core`, `llm_client`, Ansible.
  Holds the LLM API key and the SSH private key to the target. This is the only
  "smart" machine.
- **target-node01** — runs Trivy (scanner) + nginx (sample app). Gets scanned
  and patched. No agent code, no LLM, no secrets. SSH user is `aiagent`.
  Reachable only from the control node over the VCN private IP.

## Data flow
Trivy scans on the target -> JSON report -> control node -> LLM produces a plan
(remediation) or analysis (reporting) -> for remediation: validate -> human
approval -> fixed Ansible playbook patches the target -> smoke test -> rollback
on failure -> audit log.

## Safety model (do not weaken)
1. The LLM only ever returns a JSON **plan** — it never executes commands.
2. `validate_plan()` is a hard gate: JSON schema + action allow-list
   (`update_package`, `downgrade_package`) + the plan's package must match the
   finding. Anything else is rejected.
3. Nothing runs without a human `y` (`approve()`).
4. Execution is a fixed, reviewed playbook (`playbooks/patch.yml`) — the model
   cannot inject tasks.
5. A failed smoke test auto-rolls-back inside the playbook.
6. Every decision + outcome is appended to `audit.log`.

## Stack
Python 3.11 (OL8 default 3.6 is too old for the SDKs), one of
anthropic / openai / google-genai (chosen via `LLM_PROVIDER` in `.env`),
jsonschema, Trivy, Ansible. Provider is swappable with no code change.

## Files
- `config.py` — all settings from env vars (incl. `DRY_RUN`)
- `llm_client.py` — one `generate()` over Claude/GPT/Gemini
- `remediation_core.py` — parse_trivy, make_plan, validate_plan, approve, execute, audit
- `r_act.py`, `p_act.py`, `analyze.py` — the three agents
- `playbooks/patch.yml` — patch + smoke test + rollback
- `selftest.py` — local, no-target smoke test
- `sample_report.json` — sample Trivy output for local testing
- `setup_control.sh`, `setup_target.sh` — per-server installers

## Local testing
`DRY_RUN=1` makes `execute()` print the Ansible command instead of running it,
so the full pipeline can be exercised on a laptop against `sample_report.json`
with a real LLM but no SSH/Ansible/target. See DEPLOY.md.
