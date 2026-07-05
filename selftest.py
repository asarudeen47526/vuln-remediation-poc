"""Local self-test - run this on your laptop to verify the project works
WITHOUT needing the target VM. It checks, in order:

  1. config loads
  2. the sample Trivy report parses into findings
  3. the LLM is reachable (needs your API key in the environment)
  4. the LLM produces a plan that passes the safety gate

Usage:
    set LLM_PROVIDER + the matching API key in your environment, then:
    python selftest.py
"""
import os
import sys

FAIL = "\033[91mFAIL\033[0m"
OK = "\033[92mok\033[0m"


def main() -> int:
    # 1. config
    try:
        import config
        print(f"[{OK}] config loaded (provider={config.LLM_PROVIDER}, dry_run={config.DRY_RUN})")
    except Exception as e:                                     # noqa: BLE001
        print(f"[{FAIL}] config: {e}")
        return 1

    # 2. parse the sample report
    try:
        from remediation_core import parse_trivy
        here = os.path.dirname(os.path.abspath(__file__))
        findings = parse_trivy(os.path.join(here, "sample_report.json"))
        assert findings, "no findings parsed"
        print(f"[{OK}] sample_report.json parsed -> {len(findings)} findings")
    except Exception as e:                                     # noqa: BLE001
        print(f"[{FAIL}] parse: {e}")
        return 1

    # 3. LLM reachable
    try:
        from llm_client import generate
        reply = generate("Reply with exactly the word: ready", "ping").strip()
        print(f"[{OK}] LLM reachable -> {reply!r}")
    except Exception as e:                                     # noqa: BLE001
        print(f"[{FAIL}] LLM call: {e}")
        print("      Check LLM_PROVIDER and that the matching API key is set.")
        return 1

    # 4. plan + safety gate on the first finding
    try:
        from remediation_core import make_plan, validate_plan
        plan = make_plan(findings[0])
        ok, why = validate_plan(plan, findings[0])
        status = OK if ok else FAIL
        print(f"[{status}] plan for {findings[0]['cve']}: {plan}  (gate: {why})")
        if not ok:
            return 1
    except Exception as e:                                     # noqa: BLE001
        print(f"[{FAIL}] plan/validate: {e}")
        return 1

    print("\nAll checks passed. The LLM path and safety gate work locally.")
    print("Next: run `python analyze.py sample_report.json` to generate a report,")
    print("or `DRY_RUN=1 python p_act.py` after pointing REPORT_PATH at the sample.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
