"""Central configuration. Everything is overridable via environment variables
(see .env.example). Nothing secret is hard-coded here."""
import os

# Load .env from the project root automatically so scripts work when run
# directly (python analyze.py) without pre-loading the environment.
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/vulndb")

_env_file = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(_env_file):
    with open(_env_file, encoding="utf-8") as _fh:
        for _line in _fh:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line:
                continue
            _k, _, _v = _line.partition("=")
            _v = _v.split(" #")[0].strip()  # strip inline comments
            os.environ.setdefault(_k.strip(), _v)  # don't override existing env vars

# --- LLM provider selection -------------------------------------------------
# One of: "anthropic" | "openai" | "gemini". The matching API key is read from
# the environment by that provider's own SDK (see llm_client.py / .env.example).
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic").lower()
# Optional explicit model id; if empty a sane per-provider default is used.
LLM_MODEL = os.getenv("LLM_MODEL", "")
# Auto-analysis toggle.  AI_ENABLED=0 (default) disables automatic LLM calls
# after import — analysis, plan generation, and grouping only run when triggered
# on-demand from the UI.  Set AI_ENABLED=1 in .env and restart to have the app
# automatically analyze findings on every import.
AI_ENABLED = os.getenv("AI_ENABLED", "0") == "1"

# --- Target VM (the machine being remediated) -------------------------------
TARGET_HOST = os.getenv("TARGET_HOST", "10.0.0.20")
SSH_USER = os.getenv("SSH_USER", "patch-agent")
SSH_KEY = os.path.expanduser(os.getenv("SSH_KEY", "~/.ssh/id_patch"))
# Optional SSH jump/bastion host — set to "user@host" or just "host" when the
# target is on a private network not directly reachable from this machine.
JUMP_HOST = os.getenv("JUMP_HOST", "")
# Full path to Trivy binary on the TARGET node.
TRIVY_PATH = os.getenv("TRIVY_PATH", "/usr/local/bin/trivy")
# If set, R-Act/P-Act pull the Trivy report directly from this path on the
# TARGET over SCP instead of watching a local file.  Example: /tmp/trivy_scan.json
REMOTE_REPORT_PATH = os.getenv("REMOTE_REPORT_PATH", "")


def ssh_opts(jump_host: str = "") -> list:
    """Standard SSH CLI flags shared by all agents (SSH and SCP alike)."""
    opts = [
        "-i", SSH_KEY,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        "-o", "BatchMode=yes",
    ]
    jh = jump_host or JUMP_HOST
    if jh:
        opts += ["-J", jh]
    return opts
HEALTH_URL = os.getenv("HEALTH_URL", "http://localhost/health")

# --- Safety: the only actions the agent is ever allowed to execute ----------
# manual_required = cannot be automated; agent prints instructions for operator
ALLOWED_ACTIONS = {"update_package", "downgrade_package", "manual_required"}

# --- Playbook routing by install method -------------------------------------
# Maps install_method (returned by LLM plan + server_inspector) to the Ansible
# playbook that knows how to remediate it.  None = cannot be automated.
_PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "playbooks")
PLAYBOOK_MAP = {
    # ── RHEL-native — air-gapped: all updates from local DNF repos ───────────
    # AppStream module stream update (RHEL 8/9): dnf module update <module>:<stream>
    "dnf_module":   os.path.join(_PLAYBOOKS_DIR, "patch_dnf_module.yml"),
    # Standard dnf update against local repo: dnf update <pkg>
    "dnf":          os.path.join(_PLAYBOOKS_DIR, "patch_dnf.yml"),
    # RPM in DB but no enabled local repo: install newer .rpm from internal source
    "rpm_manual":   os.path.join(_PLAYBOOKS_DIR, "patch_rpm_manual.yml"),
    # Advisory-targeted patching requires Red Hat CDN — disabled (air-gapped)
    "dnf_advisory": None,
    # ── Application-level package managers ──────────────────────────────────
    "pip":          os.path.join(_PLAYBOOKS_DIR, "patch_pip.yml"),
    "npm":          os.path.join(_PLAYBOOKS_DIR, "patch_npm.yml"),
    "gem":          os.path.join(_PLAYBOOKS_DIR, "patch_gem.yml"),
    # ── Cannot be automated — operator must follow manual_steps ─────────────
    "scl":          None,   # Red Hat Software Collections (RHEL 7)
    "tarball":      None,
    "source":       None,
    "vendor":       None,
    "container":    None,
    "unknown":      None,
}
SEVERITIES = {"HIGH", "CRITICAL"}

# --- Local testing ----------------------------------------------------------
# DRY_RUN=1 makes execute() print the Ansible command instead of running it, so
# you can exercise the full scan -> plan -> validate -> approve pipeline on your
# laptop without SSH/Ansible/a live target. Set DRY_RUN=0 on the control node.
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

# --- Paths / cadence --------------------------------------------------------
PLAYBOOK = os.path.join(os.path.dirname(__file__), "playbooks", "patch.yml")
AUDIT_LOG = os.getenv("AUDIT_LOG", os.path.join(os.path.dirname(__file__), "audit.log"))
REPORT_PATH = os.path.expanduser(os.getenv("REPORT_PATH", "~/incoming/scan.json"))
WATCH_INTERVAL = int(os.getenv("WATCH_INTERVAL", "15"))     # R-Act poll seconds
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "3600"))    # P-Act scan cadence
