"""Gather runtime context from the target server over SSH (read-only).

Called before any LLM analysis so the model understands what is actually
running on the host -- not just what packages are installed.  All commands
are non-destructive and require no elevated privileges beyond what aiagent
normally has.
"""
import subprocess

from config import JUMP_HOST, SSH_KEY, SSH_USER, TARGET_HOST, ssh_opts


# ---------------------------------------------------------------------------
# Low-level SSH runner
# ---------------------------------------------------------------------------

def _run(cmd: str, host: str = TARGET_HOST, user: str = SSH_USER,
         jump_host: str = "") -> str:
    """Run a single command on `host` over SSH; return stdout or '' on error."""
    try:
        r = subprocess.run(
            ["ssh"] + ssh_opts(jump_host) + [f"{user}@{host}", cmd],
            capture_output=True, text=True, timeout=25,
        )
        return r.stdout.strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Context gatherer
# ---------------------------------------------------------------------------

def gather(host: str = TARGET_HOST, user: str = SSH_USER,
           jump_host: str = "") -> dict:
    """SSH into `host` and collect read-only runtime context.

    Returns a dict with keys: os, hostname, services, ports, apps,
    lib_procs, uptime.  Any key whose command fails is an empty string.
    """
    ctx: dict[str, str] = {}

    # OS + kernel
    ctx["os"] = _run(
        r"cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION|ID)=' | tr -d '\"'",
        host, user, jump_host,
    )
    ctx["hostname"] = _run("hostname && uname -r", host, user, jump_host)
    ctx["uptime"]   = _run("uptime", host, user, jump_host)

    # Systemd running services
    ctx["services"] = _run(
        "systemctl list-units --type=service --state=running --no-pager --no-legend "
        "2>/dev/null | awk '{print $1}' | grep -v '@' | head -25",
        host, user, jump_host,
    )

    # Listening TCP ports + owning process names
    ctx["ports"] = _run(
        "ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $1, $4, $7}' | head -15",
        host, user, jump_host,
    )

    # Application versions relevant to the scan
    ctx["apps"] = _run(
        "nginx -v 2>&1 || true; "
        "rpm -q nginx curl openssl sudo python3 2>/dev/null "
        "| grep -v 'not installed' || true",
        host, user, jump_host,
    )

    # Processes that have libcurl or libssl mapped in memory
    # (tells us what needs a restart after patching)
    ctx["lib_procs"] = _run(
        "lsof 2>/dev/null | grep -E 'libcurl|libssl|libcrypto' "
        "| awk '{print $1}' | sort -u | head -10 || true",
        host, user, jump_host,
    )

    return ctx


# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------

def format_for_prompt(ctx: dict) -> str:
    """Render the context dict as a readable plain-text block for LLM prompts."""
    def indent(s: str) -> str:
        return s.replace("\n", "\n  ")

    sections = []
    if ctx.get("hostname"):
        sections.append(f"Hostname / kernel : {ctx['hostname']}")
    if ctx.get("os"):
        sections.append(f"OS                : {ctx['os']}")
    if ctx.get("uptime"):
        sections.append(f"Uptime            : {ctx['uptime']}")
    if ctx.get("services"):
        sections.append(f"Running services  :\n  {indent(ctx['services'])}")
    if ctx.get("ports"):
        sections.append(f"Listening ports   :\n  {indent(ctx['ports'])}")
    if ctx.get("apps"):
        sections.append(f"Application versions:\n  {indent(ctx['apps'])}")
    if ctx.get("lib_procs"):
        sections.append(
            f"Processes with libcurl/libssl in memory (restart candidates):\n"
            f"  {indent(ctx['lib_procs'])}"
        )
    return "\n\n".join(sections) if sections else "(context unavailable)"
