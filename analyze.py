"""Analysis agent (read-only).

Runs on the CONTROL node or directly from a local machine with SSH access.
Scans the target (or pulls / reads an existing Trivy JSON report), gathers
server runtime context, then sends a COMPACT AGGREGATED payload to the LLM
for a holistic risk and batch-remediation analysis.  It NEVER remediates --
that is R-Act / P-Act.

Usage:
    python analyze.py                              # SSH to target, run Trivy, analyze
    python analyze.py --pull                       # pull existing /tmp/trivy_scan.json from target
    python analyze.py --pull /path/on/target       # pull a specific remote report path
    python analyze.py report.json                  # analyze an existing local Trivy JSON file
    python analyze.py report.json --ait-id AIT-001 # analyze and store results to DB
    python analyze.py report.json --dry            # print grouped payload, skip LLM call
    DRY_RUN=1 python analyze.py report.json        # same via env var

Set JUMP_HOST=user@bastion in .env when the target is not directly reachable.
Set REMOTE_REPORT_PATH=/tmp/trivy_scan.json if Trivy already runs on the target
via cron and writes there.
"""
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter

import context_collector
from config import DRY_RUN, JUMP_HOST, SSH_KEY, SSH_USER, TARGET_HOST, TRIVY_PATH, ssh_opts
from llm_client import generate
from remediation_core import parse_trivy

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
LOCAL_SCAN   = os.path.join(tempfile.gettempdir(), "analyze_scan.json")

# ---------------------------------------------------------------------------
# Package family normalization
# ---------------------------------------------------------------------------

# Prefixes where all sub-packages belong to one remediation unit (same errata)
_PREFIX_FAMILIES = (
    "kernel", "perl", "python3", "python2", "python",
    "java", "openjdk", "nodejs", "node", "ruby",
    "openssl", "libssl", "nss", "curl", "libcurl",
    "glibc", "gcc", "php", "go", "rust",
)

# Sub-package suffixes that don't change the remediation unit
_SUFFIX_RE = re.compile(
    r"-(?:core|devel|modules|headers|libs|lib|common|tools|utils|plugins|"
    r"doc|docs|man|static|debug|debuginfo|tests|test|extra|extras|all|"
    r"bin|dev|client|server|minimal|base)$"
)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _pkg_family(pkg: str) -> str:
    """Normalize a package name to its remediation family group.

    Maven-style names (containing ':') are already specific — returned as-is.
    kernel-core, kernel-devel, kernel-modules, kernel-headers all collapse to 'kernel'.
    perl-CGI, perl-CPAN, etc. collapse to 'perl'.
    """
    if ":" in pkg:
        return pkg
    lower = pkg.lower()
    for prefix in _PREFIX_FAMILIES:
        if lower == prefix or lower.startswith(prefix + "-"):
            return prefix
    # Strip common sub-package suffixes iteratively (e.g. foo-libs-devel → foo)
    stripped = pkg
    while True:
        new = _SUFFIX_RE.sub("", stripped)
        if new == stripped:
            break
        stripped = new
    return stripped or pkg


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate_findings(findings: list[dict]) -> list[dict]:
    """Collapse individual findings into remediation groups by package family.

    Each group has:
      group         — family name (the patch unit)
      packages      — sorted list of sub-package names in this group
      cve_count     — total findings collapsed into this group
      max_severity  — worst severity across the group (CRITICAL > HIGH)
      target_version — representative fixed version (highest seen)
      reboot        — True for kernel family, False otherwise
      sample_cves   — up to 3 representative CVE IDs

    Sorted: no-reboot quick-wins first, reboot-required last;
    CRITICAL before HIGH within each tier.
    """
    buckets: dict[str, dict] = {}
    for f in findings:
        family = _pkg_family(f["package"])
        if family not in buckets:
            buckets[family] = {
                "group": family,
                "packages": set(),
                "cve_count": 0,
                "max_severity": f["severity"],
                "_sev_rank": _SEV_ORDER.get(f["severity"], 9),
                "target_version": f.get("fixed") or "",
                "reboot": family.startswith("kernel"),
                "sample_cves": [],
            }
        g = buckets[family]
        g["packages"].add(f["package"])
        g["cve_count"] += 1
        rank = _SEV_ORDER.get(f["severity"], 9)
        if rank < g["_sev_rank"]:
            g["_sev_rank"] = rank
            g["max_severity"] = f["severity"]
        fv = f.get("fixed") or ""
        if fv and fv > g["target_version"]:
            g["target_version"] = fv
        cve = f.get("cve", "")
        if cve and len(g["sample_cves"]) < 3 and cve not in g["sample_cves"]:
            g["sample_cves"].append(cve)

    result = []
    for g in buckets.values():
        del g["_sev_rank"]
        g["packages"] = sorted(g["packages"])
        result.append(g)

    result.sort(key=lambda g: (
        g["reboot"],
        _SEV_ORDER.get(g["max_severity"], 9),
        g["group"],
    ))
    return result


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

SYSTEM = (
    "You are a vulnerability analyst for RHEL-family Linux servers. "
    "For EACH CVE in the findings list, output exactly one block:\n\n"
    "### {CVE-ID}\n"
    "- **Risk**: one sentence — severity level and real exposure on this host\n"
    "- **Exploitability**: one sentence — realistic attack path given the services running\n"
    "- **Service Impact**: one sentence — which service or component is affected\n"
    "- **Fix Note**: one sentence — patch command, restart needed, expected downtime\n\n"
    "Output blocks in CRITICAL-first order. "
    "No preamble, no summary, no extra sections. "
    "Use server runtime context (if provided) to make each sentence specific to this host."
)


MAX_FINDINGS = 60   # cap prompt size; truncation is noted to the LLM


def llm_analysis(findings: list[dict], context_text: str = "") -> str:
    """Send per-CVE findings to the LLM and get a compact 4-bullet analysis per CVE."""
    compact = [
        {"cve": f["cve"], "pkg": f["package"], "sev": f["severity"],
         "installed": f["installed"], "fixed": f.get("fixed", "")}
        for f in findings[:MAX_FINDINGS]
    ]
    note = ("" if len(findings) <= MAX_FINDINGS else
            f"\n\n(Showing first {MAX_FINDINGS} of {len(findings)} findings.)")

    parts: list[str] = []
    if context_text:
        parts.append(f"## Server runtime context\n\n{context_text}")
    parts.append(
        "## Findings\n\n"
        f"```json\n{json.dumps(compact, indent=2)}\n```{note}\n\n"
        "Produce a compact ### CVE-ID block for each finding."
    )
    return generate(SYSTEM, "\n\n".join(parts))


# ---------------------------------------------------------------------------
# Report builder  (full findings table preserved for audit reference)
# ---------------------------------------------------------------------------

def build_report(findings: list, by_sev: dict, fixable: list,
                 analysis: str, context_text: str) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    groups = aggregate_findings(findings)
    out = [
        "# Vulnerability Analysis Report", "",
        f"- **Target:** {TARGET_HOST}",
        f"- **Generated:** {ts}",
        f"- **Total HIGH/CRITICAL findings:** {len(findings)}",
        f"- **Critical:** {by_sev.get('CRITICAL', 0)}"
        f"  |  **High:** {by_sev.get('HIGH', 0)}",
        f"- **Fixes available (quick wins):** {len(fixable)}",
        f"- **Remediation groups:** {len(groups)}", "",
    ]

    if context_text:
        out += ["## Server context", "", "```", context_text, "```", ""]

    out += ["## Analyst assessment", "", analysis.strip(), ""]

    out += [
        "## Remediation groups (aggregated)", "",
        "| Group | Packages | CVEs | Max Severity | Reboot |",
        "|---|---|---|---|---|",
    ]
    for g in groups:
        out.append(
            f"| {g['group']} | {', '.join(g['packages'])} | {g['cve_count']} "
            f"| {g['max_severity']} | {'Yes' if g['reboot'] else 'No'} |"
        )
    out.append("")

    out += [
        "## All findings (raw — not sent to LLM)", "",
        "| CVE | Package | Severity | Installed | Fixed |",
        "|---|---|---|---|---|",
    ]
    for f in sorted(findings, key=lambda x: (_SEV_ORDER.get(x["severity"], 9), x["package"])):
        out.append(
            f"| {f['cve']} | {f['package']} | {f['severity']} | "
            f"{f['installed']} | {f.get('fixed') or '-'} |"
        )
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Per-CVE extraction + DB persistence
# ---------------------------------------------------------------------------

def _extract_per_cve(text: str) -> dict[str, str]:
    """Extract ### CVE-* sections from LLM output.

    The holistic analysis format no longer produces per-CVE sections, so this
    returns an empty dict.  Callers fall back to storing the full batch summary
    for every finding, which is correct — the report is group-level, not per-CVE.
    The function is kept for backward compatibility with any direct callers.
    """
    per_cve: dict[str, str] = {}
    parts = re.split(r'\n(?=###\s+CVE-[\w-]+)', text)
    for part in parts:
        m = re.match(r'###\s+(CVE-[\w-]+)', part.strip())
        if m:
            per_cve[m.group(1)] = part.strip()
    return per_cve


def store_to_db(findings: list[dict], analysis_text: str, ait_id: str) -> None:
    """Write analysis to the DB findings table.

    Since the analysis is now a holistic batch report (not per-CVE), every
    finding in this AIT receives the same summary text.  Per-CVE fallback in
    _extract_per_cve returns {} for the new format, so the full text is stored.
    """
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
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    dry = DRY_RUN or "--dry" in args
    args = [a for a in args if a != "--dry"]

    # --- resolve report source ---
    if args and args[0] == "--pull":
        remote_path = args[1] if len(args) >= 2 and not args[1].startswith("--") \
            else "/tmp/trivy_scan.json"
        report_path = pull_report(remote_path)
        live = True
    elif args and not args[0].startswith("--"):
        report_path = args[0]
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
    groups  = aggregate_findings(findings)
    print(
        f"Found {len(findings)} findings "
        f"({by_sev.get('CRITICAL', 0)} critical, {len(fixable)} fixable) "
        f"-> {len(groups)} remediation groups."
    )

    # --- dry run: print aggregated payload and exit without calling LLM ---
    if dry:
        payload = {
            "host": TARGET_HOST,
            "os": "RHEL-family",
            "summary": {
                "critical": by_sev.get("CRITICAL", 0),
                "high":     by_sev.get("HIGH", 0),
                "total":    len(findings),
                "groups":   len(groups),
            },
            "remediation_groups": groups,
        }
        print("\n[DRY RUN] Aggregated payload (LLM call skipped):")
        print(json.dumps(payload, indent=2))
        return

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

    print(f"Analyzing {len(groups)} remediation groups ({len(findings)} raw findings) ...")
    analysis = llm_analysis(findings, context_text)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts_str   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(REPORTS_DIR, f"vuln_analysis_{ts_str}.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(build_report(findings, by_sev, fixable, analysis, context_text))
    print(f"Report written: {out_path}")

    # --- optionally persist analysis to DB ---
    ait_id: str | None = None
    for i, a in enumerate(args):
        if a == "--ait-id" and i + 1 < len(args):
            ait_id = args[i + 1]
            break
    if ait_id:
        store_to_db(findings, analysis, ait_id)


if __name__ == "__main__":
    main()
