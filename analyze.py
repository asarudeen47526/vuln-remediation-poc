"""Analysis agent (read-only).

Runs on the CONTROL node or directly from a local machine with SSH access.
Scans the target (or pulls / reads an existing Trivy JSON report), gathers
server runtime context, then sends everything to the LLM for a risk AND
application impact analysis.  It NEVER remediates -- that is R-Act / P-Act.

Usage:
    python analyze.py                          # SSH to target, run Trivy, analyze
    python analyze.py --pull                   # pull existing /tmp/trivy_scan.json from target
    python analyze.py --pull /path/on/target   # pull a specific remote report path
    python analyze.py report.json              # analyze an existing local Trivy JSON file
    python analyze.py report.json --ait-id AIT-001  # analyze and store per-CVE results to DB

Set JUMP_HOST=user@bastion in .env when the target is not directly reachable.
Set REMOTE_REPORT_PATH=/tmp/trivy_scan.json if Trivy already runs on the target
via cron and writes there.
"""
import datetime
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter

import context_collector
from config import JUMP_HOST, SSH_KEY, SSH_USER, TARGET_HOST, TRIVY_PATH, ssh_opts
from llm_client import generate
from remediation_core import parse_trivy

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
LOCAL_SCAN   = os.path.join(tempfile.gettempdir(), "analyze_scan.json")
MAX_FINDINGS = 60   # cap prompt size; truncation is noted to the LLM

SYSTEM = (
    "You are a vulnerability analyst for RHEL-family Linux servers. "
    "You are given scanner findings AND the server's live runtime context "
    "(OS, running services, exposed ports, installed applications). "
    "Produce a risk and impact analysis with these sections:\n\n"
    "1. **Overall risk posture** (2-3 sentences: urgency and exposure level)\n"
    "2. **Most urgent items** — prioritised by severity AND exploitability given "
    "the services actually running on this host\n"
    "3. **Application impact analysis** — for each finding:\n"
    "   (a) which running service or application is directly or indirectly at risk,\n"
    "   (b) realistic exploitation scenario in this specific environment,\n"
    "   (c) remediation impact: does patching require a service restart? "
    "any expected downtime?\n"
    "4. **Quick wins** — findings with a vendor-supplied fix already available\n"
    "5. **Recommended remediation order** with rationale\n\n"
    "Output GitHub-flavored markdown with no preamble."
)


# ---------------------------------------------------------------------------
# Remote operations
# ---------------------------------------------------------------------------

def scan_target() -> str:
    """SSH to target, run Trivy, pull the JSON report back."""
    remote = (
        f"sudo {TRIVY_PATH} rootfs --scanners vuln --pkg-types os "
        "--severity HIGH,CRITICAL --timeout 15m --quiet --format json "
        "-o /tmp/analyze.json /"
    )
    print(f"Scanning {TARGET_HOST} ...")
    subprocess.run(["ssh"] + ssh_opts() + [f"{SSH_USER}@{TARGET_HOST}", remote],
                   check=True)
    subprocess.run(["scp"] + ssh_opts() +
                   [f"{SSH_USER}@{TARGET_HOST}:/tmp/analyze.json", LOCAL_SCAN],
                   check=True)
    return LOCAL_SCAN


def pull_report(remote_path: str = "/tmp/trivy_scan.json") -> str:
    """Pull an existing Trivy JSON report from the target without re-scanning."""
    print(f"Pulling {TARGET_HOST}:{remote_path} ...")
    subprocess.run(["scp"] + ssh_opts() +
                   [f"{SSH_USER}@{TARGET_HOST}:{remote_path}", LOCAL_SCAN],
                   check=True)
    return LOCAL_SCAN


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

def llm_analysis(findings: list[dict], context_text: str = "") -> str:
    compact = [
        {"cve": f["cve"], "pkg": f["package"], "sev": f["severity"],
         "installed": f["installed"], "fixed": f["fixed"]}
        for f in findings[:MAX_FINDINGS]
    ]
    note = ("" if len(findings) <= MAX_FINDINGS else
            f"\n\n(Showing first {MAX_FINDINGS} of {len(findings)} findings.)")

    parts = []
    if context_text:
        parts.append(f"## Server runtime context\n\n{context_text}")
    parts.append(
        f"## Scanner findings\n\n"
        f"{json.dumps(compact, indent=2)}{note}\n\n"
        "Analyze the findings in the context of the server above and produce the "
        "risk + impact report."
    )
    return generate(SYSTEM, "\n\n".join(parts))


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_report(findings: list, by_sev: dict, fixable: list,
                 analysis: str, context_text: str) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    out = [
        "# Vulnerability Analysis Report", "",
        f"- **Target:** {TARGET_HOST}",
        f"- **Generated:** {ts}",
        f"- **Total HIGH/CRITICAL findings:** {len(findings)}",
        f"- **Critical:** {by_sev.get('CRITICAL', 0)}"
        f"  |  **High:** {by_sev.get('HIGH', 0)}",
        f"- **Fixes available (quick wins):** {len(fixable)}", "",
    ]

    if context_text:
        out += [
            "## Server context", "",
            "```", context_text, "```", "",
        ]

    out += [
        "## Analyst assessment", "",
        analysis.strip(), "",
        "## All findings", "",
        "| CVE | Package | Severity | Installed | Fixed |",
        "|---|---|---|---|---|",
    ]
    for f in sorted(findings,
                    key=lambda x: (x["severity"] != "CRITICAL", x["package"])):
        out.append(
            f"| {f['cve']} | {f['package']} | {f['severity']} | "
            f"{f['installed']} | {f.get('fixed') or '-'} |"
        )
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Per-CVE extraction + DB persistence
# ---------------------------------------------------------------------------

def _extract_per_cve(text: str) -> dict[str, str]:
    import re
    per_cve: dict[str, str] = {}
    parts = re.split(r'\n(?=###\s+CVE-[\w-]+)', text)
    for part in parts:
        m = re.match(r'###\s+(CVE-[\w-]+)', part.strip())
        if m:
            per_cve[m.group(1)] = part.strip()
    return per_cve


def store_to_db(findings: list[dict], analysis_text: str, ait_id: str) -> None:
    """Write per-CVE analysis sections to the DB findings table."""
    try:
        os.environ.setdefault("DATABASE_URL",
                              "postgresql://postgres:postgres@localhost:5432/vulndb")
        from app.database import SessionLocal
        from app import models
        from app.crud import update_finding

        per_cve = _extract_per_cve(analysis_text)
        db = SessionLocal()
        try:
            updated = 0
            for raw in findings:
                cve = raw["cve"]
                text = per_cve.get(cve, analysis_text)
                rows = (db.query(models.Finding)
                          .filter(models.Finding.ait_id == ait_id,
                                  models.Finding.cve_id == cve)
                          .all())
                for row in rows:
                    update_finding(db, row.id, analysis_md=text)
                    updated += 1
            print(f"  Stored analysis for {updated} finding(s) in DB (AIT {ait_id}).")
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] Could not store analysis to DB: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # --- resolve report source ---
    if len(sys.argv) >= 2 and sys.argv[1] == "--pull":
        remote_path = sys.argv[2] if len(sys.argv) >= 3 else "/tmp/trivy_scan.json"
        report_path = pull_report(remote_path)
        live = True
    elif len(sys.argv) == 2:
        report_path = sys.argv[1]   # local file passed directly
        live = False
    else:
        report_path = scan_target()
        live = True

    findings = parse_trivy(report_path)
    if not findings:
        print("No HIGH/CRITICAL findings -- nothing to analyze.")
        return

    by_sev  = Counter(f["severity"] for f in findings)
    fixable = [f for f in findings if f.get("fixed")]
    print(f"Found {len(findings)} findings "
          f"({by_sev.get('CRITICAL', 0)} critical, {len(fixable)} fixable).")

    # --- gather server context (only when connected to a live target) ---
    context_text = ""
    if live:
        print("Gathering server context ...")
        ctx = context_collector.gather()
        context_text = context_collector.format_for_prompt(ctx)
        if context_text and context_text != "(context unavailable)":
            print("Context collected.")
        else:
            print("Context unavailable (SSH may have failed) -- proceeding without it.")
            context_text = ""

    print(f"Analyzing {len(findings)} findings ...")
    analysis = llm_analysis(findings, context_text)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts_str  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(REPORTS_DIR, f"vuln_analysis_{ts_str}.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(build_report(findings, by_sev, fixable, analysis, context_text))
    print(f"Report written: {out_path}")

    # -- optionally persist per-CVE analysis to DB -------------------------
    ait_id: str | None = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--ait-id" and i + 1 < len(args):
            ait_id = args[i + 1]
            break
    if ait_id:
        store_to_db(findings, analysis, ait_id)


if __name__ == "__main__":
    main()
