"""Watch Agent — the UI-integrated pipeline agent (runs on the CONTROL NODE).

This is the agent that ties everything together for the web dashboard:

  1. Detects a new Trivy vulnerability report
       DRY_RUN=1  -> uses sample_report.json  (no SSH needed, safe for dev)
       DRY_RUN=0  -> polls target via SCP every WATCH_INTERVAL seconds
  2. Imports findings into the database  (POST /import)
       -> remediation plans are generated automatically in the background
  3. Runs LLM analysis on the findings   (analyze.py -> llm_analysis)
  4. Stores per-CVE analysis in the DB   (POST /import-analysis)

After each cycle the dashboard at http://localhost:$PORT shows:
  • All findings with severity, package, installed/fixed versions
  • Per-CVE LLM analysis in the "Agent Analysis" column
  • Remediation plans ready (or generating) -> single-click "Agent Remediate"

R-Act / P-Act still run in parallel in a terminal for the interactive
human-approval flow.  This agent only feeds the web UI.

Usage:
    python watch_agent.py          # reads .env for all settings
"""
import datetime
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

# ── .env auto-load (mirrors config.py; config.py itself does this too) ────────
_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env):
    with open(_env, encoding="utf-8") as _fh:
        for _line in _fh:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line:
                continue
            _k, _, _v = _line.partition("=")
            _v = _v.split(" #")[0].strip()
            os.environ.setdefault(_k.strip(), _v)

# ── config ────────────────────────────────────────────────────────────────────
AIT_ID         = os.getenv("AIT_ID", "AIT-001")
PORT           = int(os.getenv("PORT", "8080"))
API            = f"http://localhost:{PORT}/api/v1"
DRY_RUN        = os.getenv("DRY_RUN", "1") == "1"
AI_ENABLED     = os.getenv("AI_ENABLED", "1") == "1"

TARGET_HOST         = os.getenv("TARGET_HOST", "")
SSH_USER            = os.getenv("SSH_USER", "aiagent")
SSH_KEY             = os.path.expanduser(os.getenv("SSH_KEY", "~/.ssh/id_rsa"))
REMOTE_REPORT_PATH  = os.getenv("REMOTE_REPORT_PATH", "/tmp/trivy_scan.json")
WATCH_INTERVAL      = int(os.getenv("WATCH_INTERVAL", "30"))

PROJ          = os.path.dirname(os.path.abspath(__file__))
SAMPLE_REPORT = os.path.join(PROJ, "sample_report.json")
REPORTS_DIR   = os.path.join(PROJ, "reports")
LOCAL_CACHE   = os.path.join(tempfile.gettempdir(), "watch_agent_report.json")


# ── logging ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [WatchAgent] {msg}", flush=True)


# ── server readiness ──────────────────────────────────────────────────────────

def _wait_for_server(max_wait: int = 60) -> bool:
    """Block until the FastAPI server responds, up to max_wait seconds."""
    for i in range(max_wait):
        try:
            urllib.request.urlopen(f"{API}/applications", timeout=2)
            return True
        except Exception:
            if i == 0:
                _log("Waiting for web server to start…")
            time.sleep(1)
    return False


# ── application record ────────────────────────────────────────────────────────

def _ensure_app_exists() -> None:
    """Create the AIT_ID application record if it doesn't already exist."""
    try:
        urllib.request.urlopen(f"{API}/applications/{AIT_ID}", timeout=5)
        return  # exists
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return
    # 404 -> create it
    body = json.dumps({
        "ait_id": AIT_ID,
        "name": "web-server-prod",
        "owner_email": "ait-owner@accenture.com",
        "owner_name": "Platform Owner",
        "environment": "production",
        "host": TARGET_HOST or "localhost",
    }).encode()
    try:
        req = urllib.request.Request(
            f"{API}/applications",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
        _log(f"Created application record: {AIT_ID}")
    except Exception as exc:
        _log(f"[warn] Could not create application: {exc}")


# ── report acquisition ────────────────────────────────────────────────────────

def _pull_report() -> str | None:
    """Return path to a local Trivy JSON, or None if unavailable."""
    if DRY_RUN:
        return SAMPLE_REPORT if os.path.exists(SAMPLE_REPORT) else None

    opts = [
        "-i", SSH_KEY,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        "-o", "BatchMode=yes",
    ]
    r = subprocess.run(
        ["scp"] + opts + [f"{SSH_USER}@{TARGET_HOST}:{REMOTE_REPORT_PATH}", LOCAL_CACHE],
        capture_output=True,
    )
    if r.returncode != 0:
        _log(f"SCP failed — target unreachable? ({r.stderr.decode().strip()[:80]})")
        return None
    return LOCAL_CACHE


def _report_mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except FileNotFoundError:
        return 0.0


# ── DB state helpers ──────────────────────────────────────────────────────────

def _findings_needing_analysis() -> list[int]:
    """Return IDs of findings that have no analysis_md yet."""
    try:
        resp = urllib.request.urlopen(f"{API}/applications/{AIT_ID}/findings", timeout=10)
        findings = json.loads(resp.read())
        return [f["id"] for f in findings if not f.get("analysis_md")]
    except Exception:
        return []


def _findings_count() -> int:
    try:
        resp = urllib.request.urlopen(f"{API}/applications/{AIT_ID}/findings", timeout=10)
        return len(json.loads(resp.read()))
    except Exception:
        return 0


# ── file upload helper ────────────────────────────────────────────────────────

def _post_file(url: str, file_bytes: bytes, filename: str, content_type: str) -> dict:
    """POST bytes as a multipart/form-data file upload."""
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode() + file_bytes + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())


# ── pipeline steps ────────────────────────────────────────────────────────────

def _import_scan(report_path: str) -> int:
    """POST the Trivy JSON to /import. Returns number of findings imported."""
    try:
        with open(report_path, "rb") as fh:
            data = fh.read()
        result = _post_file(
            f"{API}/applications/{AIT_ID}/import",
            data,
            os.path.basename(report_path),
            "application/json",
        )
        return result.get("imported", 0)
    except Exception as exc:
        _log(f"[warn] Import scan failed: {exc}")
        return 0


def _trigger_plans() -> int:
    """Kick off plan generation for all pending/error findings."""
    try:
        req = urllib.request.Request(
            f"{API}/applications/{AIT_ID}/generate-plans",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read()).get("submitted", 0)
    except Exception as exc:
        _log(f"[warn] Generate-plans failed: {exc}")
        return 0


def _run_analysis(report_path: str) -> str:
    """Run LLM analysis on the Trivy report; returns markdown string."""
    sys.path.insert(0, PROJ)
    try:
        from remediation_core import parse_trivy
        from analyze import llm_analysis
    except ImportError as exc:
        _log(f"[warn] Cannot import analysis modules: {exc}")
        return ""

    findings = parse_trivy(report_path)
    if not findings:
        return ""
    _log(f"Calling LLM to analyze {len(findings)} finding(s)…")
    try:
        return llm_analysis(findings)
    except Exception as exc:
        _log(f"[warn] LLM analysis failed: {exc}")
        _log("       Set LLM_PROVIDER + API key in .env, or use the UI '🔬 Analyze' button.")
        return ""


def _store_analysis(analysis_md: str) -> int:
    """POST analysis markdown to /import-analysis; returns CVEs updated."""
    try:
        result = _post_file(
            f"{API}/applications/{AIT_ID}/import-analysis",
            analysis_md.encode("utf-8"),
            "analysis.md",
            "text/markdown",
        )
        return result.get("imported", 0)
    except Exception as exc:
        _log(f"[warn] Store analysis failed: {exc}")
        return 0


def _trigger_compute_groups() -> None:
    """Ask the LLM to group packages into logical families (runs in background on server)."""
    try:
        req = urllib.request.Request(
            f"{API}/applications/{AIT_ID}/compute-groups",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        _log("LLM package grouping triggered (background).")
    except Exception as exc:
        _log(f"[warn] compute-groups failed: {exc}")


def _save_report(analysis_md: str) -> None:
    """Write analysis markdown to reports/ directory."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"vuln_analysis_{ts}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(analysis_md)
    _log(f"Report saved: {path}")


# ── main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    mode = "DRY_RUN (sample_report.json)" if DRY_RUN else f"LIVE (polling {TARGET_HOST})"
    _log(f"Starting — AIT={AIT_ID}  mode={mode}  interval={WATCH_INTERVAL}s")
    _log(f"Dashboard → http://localhost:{PORT}")

    # ── wait for the web server ───────────────────────────────────────────────
    if not _wait_for_server():
        _log("ERROR: web server did not start within 60 s. Check logs/uvicorn.log")
        sys.exit(1)
    _log("Web server is up.")
    _ensure_app_exists()

    last_processed_mtime: float = 0.0

    while True:
        # ── In DRY_RUN mode: check once if analysis is missing ────────────────
        if DRY_RUN:
            if not AI_ENABLED:
                _log("AI_ENABLED=0 — LLM analysis and grouping skipped. Dashboard still active.")
            else:
                missing = _findings_needing_analysis()
                if missing:
                    _log(f"{len(missing)} finding(s) have no analysis — running LLM now…")
                    analysis_md = _run_analysis(SAMPLE_REPORT)
                    if analysis_md:
                        n = _store_analysis(analysis_md)
                        _log(f"Analysis stored for {n} CVE(s). Dashboard updated.")
                        _save_report(analysis_md)
                        _trigger_compute_groups()
                    else:
                        _log("Analysis skipped (LLM unavailable). "
                             "Use the UI '🔬 Analyze' button, or check LLM_PROVIDER in .env.")
                else:
                    _log("All findings have analysis. Nothing to do this cycle.")
                    _trigger_compute_groups()

            # Kick remediation plans regardless of AI_ENABLED (DRY_RUN plans need no LLM)
            submitted = _trigger_plans()
            if submitted:
                _log(f"Triggered remediation plan generation for {submitted} finding(s).")

            _log(f"Sleeping {WATCH_INTERVAL * 2}s (DRY_RUN — report never changes)…")
            time.sleep(WATCH_INTERVAL * 2)
            continue

        # ── LIVE mode: pull report from target, process if new ────────────────
        report_path = _pull_report()

        if report_path is None:
            _log(f"No report available. Retrying in {WATCH_INTERVAL}s…")
            time.sleep(WATCH_INTERVAL)
            continue

        mtime = _report_mtime(report_path)
        if mtime == last_processed_mtime:
            _log(f"Report unchanged. Sleeping {WATCH_INTERVAL}s…")
            time.sleep(WATCH_INTERVAL)
            continue

        # ── new or updated report ─────────────────────────────────────────────
        _log(f"New report detected: {report_path}")
        last_processed_mtime = mtime

        # Step 1 — import findings → plan generation starts automatically
        n = _import_scan(report_path)
        if n:
            _log(f"Imported {n} finding(s). Remediation plans generating in background…")
        else:
            submitted = _trigger_plans()
            if submitted:
                _log(f"Triggered plan generation for {submitted} existing finding(s).")

        # Step 2 — LLM analysis (only when AI is enabled)
        if AI_ENABLED:
            analysis_md = _run_analysis(report_path)
            if analysis_md:
                updated = _store_analysis(analysis_md)
                _log(f"Analysis stored for {updated} CVE(s). Dashboard updated.")
                _save_report(analysis_md)
                _trigger_compute_groups()
            else:
                _log("LLM analysis skipped. Use the UI '🔬 Analyze' button when ready.")
        else:
            _log("AI_ENABLED=0 — LLM analysis skipped. Set AI_ENABLED=1 in .env to enable.")

        _log(f"Cycle complete. Dashboard: http://localhost:{PORT}")
        time.sleep(WATCH_INTERVAL)


if __name__ == "__main__":
    main()
