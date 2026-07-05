# Copilot instructions for this repo

This is an AI-driven Linux vulnerability remediation POC with human approval.
Read `PROJECT_CONTEXT.md` for full design. Key rules when generating code here:

- Two machines: **control-node** runs the agents/Ansible/LLM (has the API key and
  SSH key); **target-node01** runs only Trivy + nginx and is scanned/patched.
  Never put agent code, LLM SDKs, or secrets on the target.
- Three agents: `r_act.py` (reactive, watches for reports), `p_act.py` (proactive,
  scans on a schedule), `analyze.py` (read-only, writes a report). R-Act and P-Act
  must share `remediation_core.py` — do not reimplement remediation in them.
- The LLM only returns a JSON plan. Always keep the safety gate: schema +
  action allow-list (`update_package`, `downgrade_package`) + package must match
  the finding, then human approval, then the fixed `playbooks/patch.yml`. Never
  let the model's output run directly as a shell command.
- Provider is chosen via `LLM_PROVIDER` env var and read in `llm_client.py`.
  Keep it provider-agnostic (anthropic / openai / google-genai).
- Target OS is Oracle Linux 8 (dnf). Control node uses Python 3.11.
- Prefer editing existing modules over adding new top-level scripts.
