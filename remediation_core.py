"""The remediation engine shared by BOTH agents (R-Act and P-Act).

Two-step pipeline for a single finding:
  Step 1 — inspect  : SSH to target, detect HOW the package is installed,
                       which services use it, what would break.
  Step 2 — plan     : LLM receives the finding + inspection context and
                       returns a strategy-aware JSON plan.
  validate           : schema + allow-list + package match (hard safety gate)
  approve            : human reviews plan + impact + restoration steps
  execute            : fixed Ansible playbook chosen by install_method
  audit              : append outcome to audit.log

The LLM only ever produces a *plan*. It never runs a command.
Failed smoke tests trigger automatic rollback inside the playbook.
"""
import datetime
import json
import os
import subprocess

import jsonschema

from config import (ALLOWED_ACTIONS, AUDIT_LOG, DRY_RUN, HEALTH_URL,
                    LLM_PROVIDER, PLAYBOOK, PLAYBOOK_MAP, SEVERITIES,
                    SSH_KEY, SSH_USER, TARGET_HOST)
from llm_client import generate
from server_inspector import PackageInspection, format_for_llm, inspect_package

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM = """You are a RHEL (Red Hat Enterprise Linux) patch-planning assistant. \
All target servers run RHEL 7, 8, or 9.  The servers are AIR-GAPPED — they have \
NO direct access to the internet or Red Hat CDN.  All package updates must come \
from internally configured DNF repositories (local Satellite mirror, Nexus, or \
ISO-synced repo).  Do NOT suggest 'dnf upgrade --advisory' or any action that \
requires internet access.

You are given a vulnerability finding AND a server-state inspection block that \
shows exactly how the package arrived on that RHEL host.

Your responsibilities:
1. Read install_method from the inspection block.
2. Choose the correct offline RHEL remediation strategy.
3. Assess service and application impact using the needs-restarting data.
4. Return a single JSON remediation plan — nothing else, no prose.

RHEL remediation strategies by install_method:

  dnf_module   — AppStream module stream (RHEL 8/9, PREFERRED for stream packages).
                 action: update_package
                 Use: dnf module update <module>:<stream>
                 Set module_stream field (e.g. "nodejs:18", "python39:3.9").
                 The local repo must contain the updated module stream packages.

  dnf          — Standard dnf update against local repo.
                 action: update_package
                 Use: dnf update <pkg>
                 This is the primary method for all non-module RPM packages.
                 Works as long as the local DNF repo has a newer version.

  rpm_manual   — In RPM DB but no enabled local repo.
                 action: update_package
                 Use: rpm -U <newer.rpm>
                 Set rpm_url to the internal distribution path (Satellite, shared
                 drive, or internal file server URL — NOT Red Hat CDN).

  pip          — Python package manager (application-level).
                 action: update_package
                 Use: pip3 install --upgrade <pkg>
                 Set pip_package if pip name differs from RPM/CVE name.
                 Ensure internal PyPI mirror is configured if internet is unavailable.

  npm          — Node.js global package.
                 action: update_package
                 Use: npm install -g <pkg>@latest
                 Ensure internal npm registry is configured.

  gem          — Ruby gem.
                 action: update_package
                 Use: gem update <pkg>

  scl          — Red Hat Software Collection (RHEL 7).
                 action: manual_required — SCL packages need scl enable wrapper.

  tarball / source / vendor / unknown
               → action: manual_required
                 Populate manual_steps with RHEL-specific operator instructions.

For services_to_restart: use the 'Needs restart' list from the inspection \
(produced by needs-restarting -s, the RHEL-native tool).  Only list systemd \
service names.

For reboot_required: set true when the inspection shows 'Reboot required: YES'.

For restore_plan: describe the automatic rollback — 'dnf history undo last' \
restores the exact previous package set; then listed services restart.

For impact_assessment: reference which RHEL services/apps will be affected \
based on the RPM dependents and impacted services lists.

RHSA advisory IDs in the inspection block are informational only (from local repo \
metadata).  Do NOT set install_method to 'dnf_advisory' — that method requires \
internet access and is disabled.

Respond with ONLY a JSON object — no prose, no markdown fences."""

# ── Plan schema ───────────────────────────────────────────────────────────────

PLAN_SCHEMA = {
    "type": "object",
    "required": ["action", "package", "install_method", "remediation_strategy",
                 "impact_assessment", "reboot_required", "services_to_restart",
                 "reason", "restore_plan"],
    "properties": {
        "action":               {"type": "string",
                                 "enum": list(ALLOWED_ACTIONS)},
        "package":              {"type": "string", "minLength": 1},
        "install_method":       {"type": "string"},
        "remediation_strategy": {"type": "string"},
        "impact_assessment":    {"type": "string"},
        "reboot_required":      {"type": "boolean"},
        "services_to_restart":  {"type": "array", "items": {"type": "string"}},
        "reason":               {"type": "string"},
        "restore_plan":         {"type": "string"},
        # RHEL-specific extras
        "rhsa_advisory":        {"type": "string"},   # e.g. "RHSA-2024:1234"
        "module_stream":        {"type": "string"},   # e.g. "python39:3.9"
        # Other per-method extras
        "rpm_url":              {"type": "string"},
        "pip_package":          {"type": "string"},
        "npm_package":          {"type": "string"},
        "manual_steps":         {"type": "string"},
    },
    "additionalProperties": True,
}


# ── Parsers ───────────────────────────────────────────────────────────────────

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
    """Parse a CSV vulnerability report into the same flat format as parse_trivy."""
    import csv
    import io

    if isinstance(path_or_content, (bytes, bytearray)):
        text = path_or_content.decode("utf-8-sig", errors="replace")
    elif isinstance(path_or_content, str) and "\n" not in path_or_content and len(path_or_content) < 500:
        with open(path_or_content, encoding="utf-8-sig", errors="replace") as fh:
            text = fh.read()
    else:
        text = path_or_content

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []

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


# ── Two-step plan generation ──────────────────────────────────────────────────

def make_plan(finding: dict, context_text: str = "") -> dict:
    """Step 1: SSH inspect → Step 2: LLM generates strategy-aware plan.

    The inspection result is attached to the plan as `_inspection` so
    execute() can use it without re-running SSH.
    """
    # ── Step 1: Server inspection ─────────────────────────────────────────────
    inspection: PackageInspection | None = None
    server_ctx = ""
    try:
        inspection = inspect_package(finding["package"])
        server_ctx = format_for_llm(inspection)
    except Exception as exc:
        server_ctx = f"[Server inspection failed: {exc}]"

    # Combine caller-supplied context with inspection results
    full_context = "\n\n".join(filter(None, [server_ctx, context_text]))

    # ── Step 2: LLM plan ─────────────────────────────────────────────────────
    installed = finding.get("installed", "unknown")
    user = (
        f"Vulnerability finding:\n{json.dumps(finding, indent=2)}\n\n"
        f"RHEL server inspection:\n{full_context}\n\n"
        "Produce an air-gapped RHEL remediation plan as a JSON object with these fields:\n"
        "{\n"
        '  "action": "update_package" | "downgrade_package" | "manual_required",\n'
        '  "package": "<exact package name from the finding>",\n'
        '  "install_method": "<dnf_module|dnf|rpm_manual|pip|npm|gem|scl|tarball|source|vendor|unknown>",\n'
        '  "remediation_strategy": "<exact command to run on RHEL, e.g. dnf update <pkg> or dnf module update <module>:<stream>>",\n'
        '  "impact_assessment": "<which RHEL services/apps are affected and how>",\n'
        '  "reboot_required": true | false,\n'
        '  "services_to_restart": ["<systemd-service-name>", ...],\n'
        '  "reason": "<why this CVE is exploitable and why this remediation approach>",\n'
        f'  "restore_plan": "<auto-rollback: dnf history undo last restores {installed}, then listed services restart>",\n'
        '  "module_stream": "<module:stream — required for dnf_module method, e.g. nodejs:18>",\n'
        '  "manual_steps": "<RHEL operator instructions — required for manual_required>",\n'
        '  "rpm_url": "<internal .rpm path or URL — for rpm_manual only (NOT Red Hat CDN)>",\n'
        '  "pip_package": "<pip package name — only when it differs from the RPM package name>"\n'
        "}\n"
        "IMPORTANT: Do NOT use install_method 'dnf_advisory' — internet/CDN is not available."
    )
    raw = generate(SYSTEM, user).strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw[raw.find("{"):raw.rfind("}") + 1]
    plan = json.loads(raw)

    # Attach inspection summary for execute() and audit
    if inspection:
        plan.setdefault("install_method", inspection.install_method)
        plan["_inspection"] = {
            "impacted_services":  inspection.impacted_services,
            "dependent_packages": inspection.dependent_packages,
            "current_version":    inspection.current_version,
        }

    return plan


# ── Validation ────────────────────────────────────────────────────────────────

def validate_plan(plan: dict, finding: dict) -> tuple[bool, str]:
    """Hard safety gate — nothing gets past that isn't allow-listed."""
    try:
        jsonschema.validate(plan, PLAN_SCHEMA)
    except jsonschema.ValidationError as e:
        return False, f"schema: {e.message}"

    if plan["action"] not in ALLOWED_ACTIONS:
        return False, f"action not allowed: {plan['action']}"

    # For automated methods the package name must match exactly.
    # For manual_required actions a mismatch is a warning, not a hard block.
    method = plan.get("install_method", "dnf")
    if method not in ("tarball", "source", "vendor", "container", "unknown"):
        if plan["package"] != finding.get("package"):
            return False, "plan package does not match the finding"

    return True, "ok"


# ── Human approval ────────────────────────────────────────────────────────────

def approve(plan: dict, finding: dict, source: str) -> bool:
    """Show a formatted plan and prompt for approval."""
    services = ", ".join(plan.get("services_to_restart") or []) or "none"
    reboot   = "YES" if plan.get("reboot_required") else "no"
    method   = plan.get("install_method", "unknown")

    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║                   REMEDIATION PLAN                      ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"  CVE            : {finding.get('cve')}  [{finding.get('severity')}]")
    print(f"  Package        : {plan['package']}")
    print(f"  Install method : {method}")
    print(f"  Action         : {plan['action']}")
    print(f"  Strategy       : {plan.get('remediation_strategy', '')}")
    if finding.get("installed"):
        print(f"  Current ver    : {finding['installed']}")
    if finding.get("fixed"):
        print(f"  Target ver     : {finding['fixed']}")
    print(f"  Services       : {services}")
    print(f"  Reboot         : {reboot}")
    print(f"  Impact         : {plan.get('impact_assessment', 'not assessed')}")
    print(f"  Reason         : {plan.get('reason', '')}")

    if plan["action"] == "manual_required":
        print()
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║           MANUAL STEPS (cannot be automated)            ║")
        print("  ╚══════════════════════════════════════════════════════════╝")
        print(f"  {plan.get('manual_steps', plan.get('remediation_strategy', 'See reason'))}")
    else:
        print()
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║         RESTORATION PLAN  (auto if smoke test fails)    ║")
        print("  ╚══════════════════════════════════════════════════════════╝")
        print(f"  {plan.get('restore_plan', 'automatic rollback on failure')}")

    print()
    return input(f"  Approve remediation from {source}? [y/N] ").strip().lower() == "y"


# ── Playbook selection ────────────────────────────────────────────────────────

def select_playbook(plan: dict) -> str | None:
    """Return the Ansible playbook path for this plan, or None if manual only."""
    method = plan.get("install_method", "dnf")
    return PLAYBOOK_MAP.get(method, PLAYBOOK_MAP.get("unknown"))


def build_ansible_cmd(plan: dict) -> list[str]:
    """Build the ansible-playbook command for a given plan."""
    playbook = select_playbook(plan)
    if not playbook:
        return []

    services_str = ",".join(plan.get("services_to_restart") or [])
    cmd = [
        "ansible-playbook", "-i", f"{TARGET_HOST},", playbook,
        "-u", SSH_USER, "--private-key", SSH_KEY,
        "-e", f"pkg={plan['package']}",
        "-e", f"health_url={HEALTH_URL}",
        "-e", f"services_to_restart={services_str}",
    ]

    method = plan.get("install_method", "dnf")

    # RHEL AppStream module stream (RHEL 8/9)
    if method == "dnf_module":
        module_stream = plan.get("module_stream", "")
        if module_stream:
            cmd += ["-e", f"module_stream={module_stream}"]

    # Manual RPM upgrade (internal .rpm source)
    elif method == "rpm_manual":
        rpm_url = plan.get("rpm_url", "")
        if rpm_url:
            cmd += ["-e", f"rpm_url={rpm_url}"]

    # Language package managers
    elif method == "pip":
        pip_pkg = plan.get("pip_package", "")
        if pip_pkg:
            cmd += ["-e", f"pip_package={pip_pkg}"]
    elif method == "npm":
        npm_pkg = plan.get("npm_package", "")
        if npm_pkg:
            cmd += ["-e", f"npm_package={npm_pkg}"]

    return cmd


# ── Execution ─────────────────────────────────────────────────────────────────

def execute(plan: dict) -> int:
    """Run the correct Ansible playbook for the plan's install_method.

    Returns the ansible-playbook exit code (0 = success).
    For manual_required actions prints operator steps and returns 0.
    """
    if plan["action"] == "manual_required":
        print()
        print("  [MANUAL REQUIRED] This installation cannot be automated.")
        print(f"  Install method: {plan.get('install_method', 'unknown')}")
        print()
        steps = plan.get("manual_steps") or plan.get("remediation_strategy") or plan.get("reason")
        for line in (steps or "").splitlines():
            print(f"    {line}")
        return 0

    cmd = build_ansible_cmd(plan)
    if not cmd:
        print(f"  [ERROR] No playbook mapped for install_method={plan.get('install_method')}")
        return 1

    if DRY_RUN:
        print("  [DRY_RUN] would execute:", " ".join(cmd))
        return 0

    return subprocess.run(cmd).returncode


# ── Audit ─────────────────────────────────────────────────────────────────────

def audit(source: str, finding: dict, plan, status: str) -> None:
    with open(AUDIT_LOG, "a") as fh:
        fh.write(json.dumps({
            "ts":             datetime.datetime.utcnow().isoformat(timespec="seconds"),
            "source":         source,
            "provider":       LLM_PROVIDER,
            "cve":            finding.get("cve"),
            "package":        finding.get("package"),
            "install_method": (plan or {}).get("install_method", "unknown") if plan else "unknown",
            "plan":           plan,
            "status":         status,
        }) + "\n")


# ── Full pipeline ─────────────────────────────────────────────────────────────

def handle(finding: dict, source: str, context_text: str = "") -> None:
    """Full two-step pipeline for one finding. Used by R-Act and P-Act."""
    print(f"\n=== [{source}] {finding.get('cve')} in {finding.get('package')} "
          f"({finding.get('severity')}) ===")
    try:
        plan = make_plan(finding, context_text)
    except Exception as e:
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
