# CLAUDE.md

See `PROJECT_CONTEXT.md` for the authoritative design. Quick rules:

- **control-node** = agents + Ansible + LLM client (holds API key + SSH key).
  **target-node01** = Trivy + nginx only, scanned/patched, no secrets/agents.
- Agents: `r_act.py` (reactive), `p_act.py` (proactive), `analyze.py` (read-only
  report). R-Act/P-Act share `remediation_core.py`.
- Safety gate is non-negotiable: LLM returns JSON plan -> schema + allow-list +
  package-match -> human approval -> fixed `playbooks/patch.yml` -> smoke test ->
  rollback on failure -> `audit.log`. Never execute model output as shell.
- Provider-agnostic via `LLM_PROVIDER` (`anthropic`/`openai`/`gemini`) in `.env`.
- Test locally with `DRY_RUN=1` against `sample_report.json` (see DEPLOY.md).

Common commands:
- `python selftest.py` — local no-target smoke test
- `python analyze.py sample_report.json` — generate a report locally
- `python analyze.py` / `python p_act.py` / `python r_act.py` — live (on control node)
