"""SSH-based RHEL server inspection.

Determines HOW a package was installed and which services would be impacted
if it were updated.  RHEL-specific intelligence:

  - Detects AppStream module streams (RHEL 8/9)
  - Uses needs-restarting -s for accurate service-restart detection
  - Checks subscription-manager status (local repo access)
  - Reads RHEL version (7 / 8 / 9) so Ansible can adapt
  - Verifies RPM integrity with rpm -V
  - Reads RHSA advisory IDs from local repo metadata (informational only;
    patching uses the local DNF repo — not the Red Hat CDN)

Target environment: air-gapped RHEL servers with no direct internet access.
All package updates come from internally configured DNF repositories
(e.g., local Satellite mirror, Nexus, ISO-synced repo).

Install method classification:
  dnf_module    — delivered via AppStream module stream (RHEL 8/9, preferred)
  dnf           — in RPM DB, has enabled local repo
  rpm_manual    — in RPM DB, no enabled repo (needs local .rpm file)
  pip           — installed by pip/pip3
  npm           — installed by npm globally
  gem           — installed by gem
  scl           — Red Hat Software Collection (RHEL 7)
  tarball       — files in /opt etc., not tracked by RPM
  source        — compiled from source
  vendor        — vendor install script
  unknown       — could not be classified

In DRY_RUN=1 no SSH is attempted — a realistic mock is returned.
"""
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from config import DRY_RUN, SSH_KEY, SSH_USER, TARGET_HOST, ssh_opts


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class PackageInspection:
    package: str
    install_method: str               # see module docstring for values
    current_version: str              # full RPM NEVRA or pip version string
    new_version: str                  # available fixed version
    install_path: str                 # primary file on disk
    repo_name: str                    # source repository name
    rhel_version: str                 # e.g. "Red Hat Enterprise Linux release 8.8"
    rhsa_advisories: List[str]        = field(default_factory=list)  # ["RHSA-2024:1234", ...]
    module_stream: str                = ""     # e.g. "python39:3.9" on RHEL 8/9
    subscription_ok: bool             = True
    needs_reboot: bool                = False  # from needs-restarting -r
    impacted_services: List[str]      = field(default_factory=list)  # needs-restarting -s output
    dependent_packages: List[str]     = field(default_factory=list)  # rpm -q --whatrequires
    rpm_integrity: str                = "ok"   # "ok" | "modified" | "unknown"
    notes: str                        = ""


# ── SSH helper ────────────────────────────────────────────────────────────────

def _run_ssh(script: str, host: str = "", user: str = "", key: str = "") -> str:
    """Run a bash script on the remote RHEL host; returns stdout (never raises)."""
    opts = ssh_opts()
    cmd = ["ssh"] + opts + [f"{user or SSH_USER}@{host or TARGET_HOST}", "bash", "-s"]
    try:
        r = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=90)
        return r.stdout
    except Exception:
        return ""


# ── RHEL inspection script ────────────────────────────────────────────────────
# Single SSH round-trip.  Every section is guarded by set +e so one
# missing tool does not abort the rest.
#
# Uses __PKG__ as the package placeholder — replaced by simple str.replace()
# so bash brace syntax ({print $1}, ${VAR}, rpm queryformat %{NAME}) works
# without any Python format-string escaping.

_INSPECT_SCRIPT = r"""
set +e
PKG="__PKG__"

echo "### RHEL_VERSION ###"
cat /etc/redhat-release 2>/dev/null || echo "__UNKNOWN__"

echo "### SUBSCRIPTION ###"
subscription-manager status 2>/dev/null | grep -Ei "(Overall Status|Status)" | head -3 \
  || echo "__UNAVAILABLE__"

echo "### RPM_Q ###"
rpm -q --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$PKG" 2>/dev/null \
  || echo "__MISSING__"

echo "### RPM_REPO ###"
dnf info "$PKG" 2>/dev/null | grep -Ei "^(From repo|Repository)" | head -3 || echo "__NONE__"

echo "### DNF_AVAILABLE ###"
dnf info --available "$PKG" 2>/dev/null | grep -Ei "^(Version|Release)" | head -4 || echo "__NONE__"

echo "### UPDATEINFO ###"
dnf updateinfo list security "$PKG" 2>/dev/null | grep -v "^Last metadata" || echo "__NONE__"

echo "### MODULE_STREAM ###"
dnf module list --installed 2>/dev/null | awk 'NR>2 && NF>=2 {print $1":"$2}' \
  | grep -vi "^name:" | head -30 || echo "__NONE__"
rpm -q --queryformat '%{RELEASE}\n' "$PKG" 2>/dev/null \
  | grep -oE '\.[a-z]+[0-9]+\.' || true

echo "### RPM_FILES ###"
rpm -ql "$PKG" 2>/dev/null | grep -v "not installed" | head -5 || echo "__NONE__"

echo "### RPM_WHATREQUIRES ###"
rpm -q --whatrequires "$PKG" 2>/dev/null | grep -v "no package requires" || echo "__NONE__"

echo "### SCL ###"
ls /opt/rh/ 2>/dev/null | head -5 || echo "__NONE__"

echo "### PIP ###"
{ pip show "$PKG" 2>/dev/null || pip3 show "$PKG" 2>/dev/null; } \
  | grep -Ei "^(Name|Version|Location)" || echo "__MISSING__"

echo "### NPM ###"
npm list -g "$PKG" --depth=0 2>/dev/null | grep "$PKG" || echo "__MISSING__"

echo "### GEM ###"
gem list "$PKG" 2>/dev/null | grep -i "$PKG" || echo "__MISSING__"

echo "### TARBALL ###"
find /opt /usr/local/src /srv -maxdepth 4 -iname "${PKG}*" -type d 2>/dev/null | head -5 \
  || echo "__NONE__"

echo "### NEEDS_RESTART ###"
needs-restarting -s 2>/dev/null | awk '{print $1}' | sort -u | head -30 \
  || echo "__UNAVAILABLE__"

echo "### NEEDS_REBOOT ###"
needs-restarting -r >/dev/null 2>&1
echo "EXIT:$?"

echo "### RPM_VERIFY ###"
rpm -V "$PKG" 2>/dev/null
echo "VERIFY_EXIT:$?"
"""


def _section(output: str, name: str) -> str:
    """Extract lines between ### NAME ### markers from SSH output."""
    lines = output.splitlines()
    collecting, buf = False, []
    for line in lines:
        s = line.strip()
        if s == f"### {name} ###":
            collecting = True
            continue
        if collecting and s.startswith("### ") and s.endswith(" ###"):
            break
        if collecting:
            buf.append(line)
    return "\n".join(buf).strip()


# ── Main inspection function ──────────────────────────────────────────────────

def inspect_package(package: str, host: str = "", user: str = "", key: str = "") -> PackageInspection:
    """SSH to the RHEL target and return a full PackageInspection."""
    if DRY_RUN:
        return _dry_inspection(package)

    script = _INSPECT_SCRIPT.replace("__PKG__", package)
    output = _run_ssh(script, host, user, key)

    # ── parse each section ────────────────────────────────────────────────────
    rhel_ver_raw  = _section(output, "RHEL_VERSION")
    subscription  = _section(output, "SUBSCRIPTION")
    rpm_q         = _section(output, "RPM_Q")
    rpm_repo      = _section(output, "RPM_REPO")
    dnf_available = _section(output, "DNF_AVAILABLE")
    updateinfo    = _section(output, "UPDATEINFO")
    module_raw    = _section(output, "MODULE_STREAM")
    rpm_files     = _section(output, "RPM_FILES")
    whatrequires  = _section(output, "RPM_WHATREQUIRES")
    scl_raw       = _section(output, "SCL")
    pip_info      = _section(output, "PIP")
    npm_info      = _section(output, "NPM")
    gem_info      = _section(output, "GEM")
    tarball_dirs  = _section(output, "TARBALL")
    needs_restart = _section(output, "NEEDS_RESTART")
    needs_reboot  = _section(output, "NEEDS_REBOOT")
    rpm_verify    = _section(output, "RPM_VERIFY")

    # ── booleans ──────────────────────────────────────────────────────────────
    in_rpm       = "__MISSING__" not in rpm_q      and bool(rpm_q.strip())
    has_repo     = "__NONE__"    not in rpm_repo   and bool(rpm_repo.strip())
    has_advisory = "__NONE__"    not in updateinfo and bool(updateinfo.strip())
    in_pip       = "__MISSING__" not in pip_info   and bool(pip_info.strip())
    in_npm       = "__MISSING__" not in npm_info   and bool(npm_info.strip())
    in_gem       = "__MISSING__" not in gem_info   and bool(gem_info.strip())
    in_tarball   = "__NONE__"    not in tarball_dirs and bool(tarball_dirs.strip())
    has_scl      = "__NONE__"    not in scl_raw    and bool(scl_raw.strip())

    # ── RHSA advisory IDs ─────────────────────────────────────────────────────
    rhsa_list: List[str] = []
    if has_advisory:
        for ln in updateinfo.splitlines():
            # typical line: "RHSA-2024:1234 Important/Sec. sudo-1.9.5p2-..."
            parts = ln.split()
            for p in parts:
                if p.upper().startswith("RHSA-") or p.upper().startswith("RHBA-"):
                    rhsa_list.append(p)
        rhsa_list = list(dict.fromkeys(rhsa_list))  # deduplicate, preserve order

    # ── module stream ─────────────────────────────────────────────────────────
    module_stream = ""
    if "__NONE__" not in module_raw and module_raw.strip():
        # look for lines matching package name
        for ln in module_raw.splitlines():
            if package.lower() in ln.lower() and ":" in ln:
                module_stream = ln.strip()
                break

    # ── install method (RHEL priority order — air-gapped environment) ────────
    # Language PMs first (these are app-level, not system-level)
    if in_pip:
        method = "pip"
    elif in_npm:
        method = "npm"
    elif in_gem:
        method = "gem"
    # System RPM — AppStream module stream takes priority on RHEL 8/9
    elif in_rpm and has_repo and module_stream:
        method = "dnf_module"
    elif in_rpm and has_repo:
        method = "dnf"
    elif in_rpm:
        method = "rpm_manual"
    elif has_scl:
        method = "scl"
    elif in_tarball:
        method = "tarball"
    else:
        method = "unknown"

    # ── version strings ───────────────────────────────────────────────────────
    current_version = ""
    if in_rpm:
        current_version = rpm_q.strip().splitlines()[0]
    elif in_pip:
        for ln in pip_info.splitlines():
            if ln.lower().startswith("version:"):
                current_version = ln.split(":", 1)[1].strip()

    new_version = ""
    if dnf_available and "__NONE__" not in dnf_available:
        for ln in dnf_available.splitlines():
            if ln.lower().startswith("version"):
                new_version = ln.split(":", 1)[-1].strip()
                break

    # ── install path ─────────────────────────────────────────────────────────
    install_path = ""
    if rpm_files and "__NONE__" not in rpm_files:
        install_path = rpm_files.splitlines()[0].strip()
    elif in_tarball:
        install_path = tarball_dirs.splitlines()[0].strip()

    # ── repo name ─────────────────────────────────────────────────────────────
    repo_name = ""
    if has_repo:
        for ln in rpm_repo.splitlines():
            if ":" in ln:
                repo_name = ln.split(":", 1)[-1].strip()
                break

    # ── dependent packages ────────────────────────────────────────────────────
    dep_pkgs: List[str] = []
    if whatrequires and "__NONE__" not in whatrequires:
        dep_pkgs = [ln.strip() for ln in whatrequires.splitlines() if ln.strip()]

    # ── services needing restart (needs-restarting is RHEL-native) ────────────
    # Exit code 0 = reboot NOT needed; 1 = reboot needed
    reboot_needed = "EXIT:1" in needs_reboot

    impacted: List[str] = []
    if needs_restart and "__UNAVAILABLE__" not in needs_restart:
        impacted = [ln.strip() for ln in needs_restart.splitlines() if ln.strip()]

    # ── subscription ─────────────────────────────────────────────────────────
    sub_ok = True
    if subscription and "__UNAVAILABLE__" not in subscription:
        if any(w in subscription.lower() for w in ("unknown", "invalid", "expired", "not subscribed")):
            sub_ok = False

    # ── RPM integrity ─────────────────────────────────────────────────────────
    integrity = "unknown"
    if "VERIFY_EXIT:0" in rpm_verify:
        integrity = "ok"
    elif "VERIFY_EXIT:" in rpm_verify:
        integrity = "modified"

    # ── notes for LLM ─────────────────────────────────────────────────────────
    note_parts = []
    if rhsa_list:
        note_parts.append(
            f"RHSA advisory IDs from local repo metadata (informational): {', '.join(rhsa_list)}. "
            "Servers are air-gapped — patch via local DNF repo, not Red Hat CDN."
        )
    if module_stream:
        note_parts.append(f"Package delivered via AppStream module stream: {module_stream} — use 'dnf module update'")
    if not sub_ok:
        note_parts.append("WARNING: subscription-manager reports local repo access may be restricted")
    if dep_pkgs:
        note_parts.append(f"Packages that depend on this: {', '.join(dep_pkgs[:10])}")
    if integrity == "modified":
        note_parts.append("rpm -V detected modified package files — verify before patching")
    if method == "rpm_manual":
        note_parts.append(
            "Package is in the RPM DB but no enabled local repo found — "
            "needs a newer .rpm file sourced from internal distribution (Satellite, shared drive, etc.)."
        )
    if method in ("tarball", "scl", "source", "vendor", "unknown"):
        note_parts.append(
            "Cannot be patched by dnf/rpm — manual operator steps required (action: manual_required)."
        )

    return PackageInspection(
        package=package,
        install_method=method,
        current_version=current_version,
        new_version=new_version,
        install_path=install_path,
        repo_name=repo_name,
        rhel_version=rhel_ver_raw.splitlines()[0].strip() if rhel_ver_raw else "unknown",
        rhsa_advisories=rhsa_list,
        module_stream=module_stream,
        subscription_ok=sub_ok,
        needs_reboot=reboot_needed,
        impacted_services=impacted,
        dependent_packages=dep_pkgs,
        rpm_integrity=integrity,
        notes="\n".join(note_parts),
    )


# ── Dry-run mock ──────────────────────────────────────────────────────────────

def _dry_inspection(package: str) -> PackageInspection:
    return PackageInspection(
        package=package,
        install_method="dnf",
        current_version=f"{package}-1.0.0-1.el9_3.x86_64",
        new_version="1.0.1",
        install_path=f"/usr/bin/{package}",
        repo_name="local-rhel-9-baseos",
        rhel_version="Red Hat Enterprise Linux release 9.3 (Plow)",
        rhsa_advisories=[],
        module_stream="",
        subscription_ok=True,
        needs_reboot=False,
        impacted_services=[],
        dependent_packages=[],
        rpm_integrity="ok",
        notes="[DRY_RUN] Mock RHEL 9 inspection — no SSH connection was made. Air-gapped: local repo.",
    )


# ── LLM context formatter ─────────────────────────────────────────────────────

def format_for_llm(insp: PackageInspection) -> str:
    """Format inspection results as a structured block for the LLM prompt."""
    lines = [
        f"--- RHEL Server State: package '{insp.package}' ---",
        f"RHEL version    : {insp.rhel_version}",
        f"Subscription    : {'OK' if insp.subscription_ok else 'RESTRICTED — check subscription-manager'}",
        f"Install method  : {insp.install_method}",
        f"Current version : {insp.current_version or 'unknown'}",
        f"Available update: {insp.new_version or 'unknown (check CVE advisory)'}",
        f"Install path    : {insp.install_path or 'unknown'}",
        f"Repository      : {insp.repo_name or 'none / unknown'}",
    ]
    if insp.rhsa_advisories:
        lines.append(f"RHSA advisory IDs: {', '.join(insp.rhsa_advisories)}  "
                     f"(informational — from local repo metadata; servers are air-gapped)")
    else:
        lines.append("RHSA advisory IDs: none in local repo metadata")
    if insp.module_stream:
        lines.append(f"AppStream module: {insp.module_stream}  "
                     f"← update via 'dnf module update {insp.module_stream}'")
    if insp.impacted_services:
        lines.append(f"Needs restart   : {', '.join(insp.impacted_services)}  "
                     f"(from needs-restarting -s — RHEL-accurate)")
    else:
        lines.append("Needs restart   : none detected by needs-restarting")
    lines.append(f"Reboot required : {'YES — needs-restarting -r returned 1' if insp.needs_reboot else 'no'}")
    if insp.dependent_packages:
        lines.append(f"RPM dependents  : {', '.join(insp.dependent_packages[:10])}")
    lines.append(f"RPM integrity   : {insp.rpm_integrity} (rpm -V)")
    if insp.notes:
        lines.append(f"Notes           : {insp.notes}")
    lines.append("---")
    return "\n".join(lines)
