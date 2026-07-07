"""The remediation engine shared by BOTH agents (R-Act and P-Act).

Pipeline for a single finding:
    make_plan  -> ask the LLM for a JSON remediation plan (includes restore_plan)
    validate   -> schema + allow-list + package match  (hard safety gate)
    approve    -> show full plan + restoration plan, human types y/N
    execute    -> fixed Ansible playbook over SSH (patch + service restarts + smoke test)
    audit      -> append the decision + outcome to a log

The LLM only ever produces a *plan*. It never runs a command. A failed smoke
test triggers automatic rollback + service restarts inside the playbook.
"""
import datetime
import json
import subprocess

import jsonschema

from config import (ALLOWED_ACTIONS, AUDIT_LOG, DRY_RUN, HEALTH_URL,
                    LLM_PROVIDER, PLAYBOOK, SEVERITIES, SSH_KEY, SSH_USER,
                    TARGET_HOST)
from llm_client import generate

SYSTEM = (
    "You are a Linux patch-planning assistant for RHEL-family systems (dnf). "
    "Given one vulnerability finding and optional server context, produce a single "
    "remediation plan. You never execute anything; you only propose a plan. "
    "Prefer updating the affected package to its fixed version. "
    "For services_to_restart: list only systemd service names (e.g. 'nginx', 'sshd') "
    "that load the affected library at runtime and must be restarted after patching. "
    "For restore_plan: describe exactly what will happen automatically if the smoke test "
    "fails — which version the package will roll back to, which services will be restarted, "
    "and that no manual action is required. "
    "Respond with JSON only, no prose, no markdown fences."
)

PLAN_SCHEMA = {
    "type": "object",
    "required": ["action", "package", "reboot_required", "services_to_restart",
                 "reason", "restore_plan"],
    "properties": {
        "action":               {"type": "string"},
        "package":              {"type": "string", "minLength": 1},
        "reboot_required":      {"type": "boolean"},
        "services_to_restart":  {"type": "array", "items": {"type": "string"}},
        "reason":               {"type": "string"},
        "restore_plan":         {"type": "string"},
    },
}


def parse_trivy(path: str) -> list[dict]:
    """Normalize a Trivy JSON report into a flat list of findings."""
    with open(path) as fh:
        data = json.load(fh)
    findings = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            if v.get("Severity") in SEVERITIES:
                findings.append({
                    "cve":       v.get("VulnerabilityID"),
                    "package":   v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed":     v.get("FixedVersion"),
                    "severity":  v.get("Severity"),
                })
    return findings


def parse_csv(path_or_content) -> list[dict]:
    """Parse a CSV vulnerability report into the same flat format as parse_trivy.

    Accepts either a file path (str) or raw CSV text (bytes or str).
    Flexible column matching: handles Trivy CSV exports and custom formats.

    Required columns (case-insensitive, first match wins):
      CVE      : VulnerabilityID, cve_id, CVE, cve
      Package  : PkgName, package, Package, pkg
      Severity : Severity, severity
    Optional:
      InstalledVersion, installed_version, installed, CurrentVersion -> installed
      FixedVersion, fixed_version, fixed, TargetVersion             -> fixed
      Target, os_target, Host, Source, target                       -> os
      Status, status                                                -> status
      Title, title, Description                                     -> title
    """
    import csv
    import io

    if isinstance(path_or_content, (bytes, bytearray)):
        text = path_or_content.decode("utf-8-sig", errors="replace")
    elif isinstance(path_or_content, str) and "\n" not in path_or_content and len(path_or_content) < 500:
        # treat as file path
        with open(path_or_content, encoding="utf-8-sig", errors="replace") as fh:
            text = fh.read()
    else:
        text = path_or_content

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []

    # Build column alias map (lowercase header -> canonical key)
    _ALIASES = {
        "cve": "cve", "vulnerabilityid": "cve", "cve_id": "cve",
        "package": "package", "pkgname": "package", "pkg": "package",
        "severity": "severity",
        "installedversion": "installed", "installed_version": "installed",
        "installed": "installed", "currentversion": "installed",
        "fixedversion": "fixed", "fixed_version": "fixed",
        "fixed": "fixed", "targetversion": "fixed",
        "target": "os", "os_target": "os", "host": "os",
        "source": "os", "artifactname": "os",
        "status": "status",
        "title": "title", "description": "title",
    }
    col_map: dict[str, str] = {}
    for hdr in (reader.fieldnames or []):
        canonical = _ALIASES.get(hdr.strip().lower().replace(" ", ""))
        if canonical and canonical not in col_map.values():
            col_map[hdr] = canonical

    findings = []
    for row in reader:
        mapped: dict[str, str] = {}
        for hdr, canonical in col_map.items():
            val = (row.get(hdr) or "").strip()
            if val:
                mapped[canonical] = val

        cve = mapped.get("cve", "")
        pkg = mapped.get("package", "")
        sev = mapped.get("severity", "UNKNOWN").upper()
        if not cve or not pkg:
            continue
        if sev not in SEVERITIES:
            continue

        findings.append({
            "cve":       cve,
            "package":   pkg,
            "severity":  sev,
            "installed": mapped.get("installed", ""),
            "fixed":     mapped.get("fixed", ""),
            "os":        mapped.get("os", ""),
            "title":     mapped.get("title", cve),
            "status":    mapped.get("status", ""),
        })

    return findings


def make_plan(finding: dict, context_text: str = "") -> dict:
    ctx_block = f"\nServer context:\n{context_text}\n" if context_text else ""
    installed = finding.get("installed", "unknown")
    user = (
        f"Produce a remediation plan for this vulnerability finding:\n"
        f"{json.dumps(finding)}\n"
        f"{ctx_block}\n"
        "Respond with ONLY a JSON object:\n"
        "{\n"
        '  "action": "update_package" | "downgrade_package",\n'
        '  "package": "<exact package name from the finding>",\n'
        '  "reboot_required": true | false,\n'
        '  "services_to_restart": ["<svc1>", "<svc2>"],\n'
        '  "reason": "<why this fix, which services are affected>",\n'
        f'  "restore_plan": "<what auto-rollback will do if smoke test fails: '
        f'restore {installed} via dnf history undo last, restart listed services>"\n'
        "}"
    )
    raw = generate(SYSTEM, user).strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw[raw.find("{"):raw.rfind("}") + 1]
    return json.loads(raw)


def validate_plan(plan: dict, finding: dict) -> tuple[bool, str]:
    """Hard safety gate: nothing gets past here that isn't allow-listed."""
    try:
        jsonschema.validate(plan, PLAN_SCHEMA)
    except jsonschema.ValidationError as e:
        return False, f"schema: {e.message}"
    if plan["action"] not in ALLOWED_ACTIONS:
        return False, f"action not allowed: {plan['action']}"
    if plan["package"] != finding.get("package"):
        return False, "plan package does not match the finding"
    return True, "ok"


def approve(plan: dict, finding: dict, source: str) -> bool:
    """Show a formatted remediation + restoration plan and prompt for approval."""
    services = ", ".join(plan.get("services_to_restart") or []) or "none"
    reboot   = "YES" if plan.get("reboot_required") else "no"

    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║                   REMEDIATION PLAN                      ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"  CVE      : {finding.get('cve')}  [{finding.get('severity')}]")
    print(f"  Action   : {plan['action']}")
    print(f"  Package  : {plan['package']}")
    if finding.get("installed"):
        print(f"  Current  : {finding['installed']}")
    if finding.get("fixed"):
        print(f"  Target   : {finding['fixed']}")
    print(f"  Restart  : {services}")
    print(f"  Reboot   : {reboot}")
    print(f"  Reason   : {plan.get('reason', '')}")
    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║         RESTORATION PLAN  (auto if smoke test fails)    ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"  {plan.get('restore_plan', 'dnf history undo last (automatic rollback)')}")
    print()
    return input(f"  Approve remediation from {source}? [y/N] ").strip().lower() == "y"


def execute(plan: dict) -> int:
    """Run the fixed playbook. Returns the ansible-playbook exit code."""
    services_str = ",".join(plan.get("services_to_restart") or [])
    cmd = [
        "ansible-playbook", "-i", f"{TARGET_HOST},", PLAYBOOK,
        "-u", SSH_USER, "--private-key", SSH_KEY,
        "-e", f"pkg={plan['package']}",
        "-e", f"health_url={HEALTH_URL}",
        "-e", f"services_to_restart={services_str}",
    ]
    if DRY_RUN:
        print("  [DRY_RUN] would execute:", " ".join(cmd))
        return 0
    return subprocess.run(cmd).returncode


def audit(source: str, finding: dict, plan, status: str) -> None:
    with open(AUDIT_LOG, "a") as fh:
        fh.write(json.dumps({
            "ts":       datetime.datetime.utcnow().isoformat(timespec="seconds"),
            "source":   source,
            "provider": LLM_PROVIDER,
            "cve":      finding.get("cve"),
            "package":  finding.get("package"),
            "plan":     plan,
            "status":   status,
        }) + "\n")


def handle(finding: dict, source: str, context_text: str = "") -> None:
    """Full pipeline for one finding. Used identically by R-Act and P-Act."""
    print(f"\n=== [{source}] {finding.get('cve')} in {finding.get('package')} "
          f"({finding.get('severity')}) ===")
    try:
        plan = make_plan(finding, context_text)
    except Exception as e:                        # noqa: BLE001
        print(f"  planning error: {e}")
        audit(source, finding, None, "plan_error")
        return

    ok, why = validate_plan(plan, finding)
    if not ok:
        print(f"  REJECTED: {why}")
        audit(source, finding, plan, f"rejected:{why}")
        return

    if not approve(plan, finding, source):
        print("  skipped by user")
        audit(source, finding, plan, "skipped")
        return

    rc = execute(plan)
    status = "success" if rc == 0 else "failed_rolled_back"
    print(f"  {status.upper()}")
    audit(source, finding, plan, status)
