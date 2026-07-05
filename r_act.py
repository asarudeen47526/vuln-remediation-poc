"""R-Act - REACTIVE agent.

Trigger: a Trivy scan report appears (locally or pulled from the target).
The moment new HIGH/CRITICAL findings are detected, R-Act gathers server
context and runs the shared remediation pipeline (with user approval).

Two report-source modes (set in .env):
  REMOTE_REPORT_PATH set   -> poll target via SCP for that file (recommended
                              for control-node deployments where Trivy runs on
                              the target via cron and writes to a fixed path)
  REMOTE_REPORT_PATH unset -> watch REPORT_PATH on the local filesystem
                              (original behaviour; useful for push-based setups)
"""
import os
import subprocess
import tempfile
import time

import context_collector
from config import (JUMP_HOST, REMOTE_REPORT_PATH, REPORT_PATH, SSH_USER,
                    TARGET_HOST, WATCH_INTERVAL, ssh_opts)
from remediation_core import handle, parse_trivy

LOCAL_CACHE = os.path.join(tempfile.gettempdir(), "r_act_report.json")


# ---------------------------------------------------------------------------
# Report acquisition
# ---------------------------------------------------------------------------

def _pull_from_target(remote_path: str) -> bool:
    """SCP the report from the target to LOCAL_CACHE. Returns True on success."""
    r = subprocess.run(
        ["scp"] + ssh_opts() +
        [f"{SSH_USER}@{TARGET_HOST}:{remote_path}", LOCAL_CACHE],
        capture_output=True,
    )
    return r.returncode == 0


def _report_changed(path: str, seen_mtime: float) -> tuple[bool, float]:
    """Return (changed, new_mtime) for a local file."""
    try:
        mtime = os.path.getmtime(path)
        return mtime != seen_mtime, mtime
    except FileNotFoundError:
        return False, seen_mtime


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    remote = bool(REMOTE_REPORT_PATH)
    if remote:
        print(f"R-Act (reactive): polling {TARGET_HOST}:{REMOTE_REPORT_PATH} "
              f"every {WATCH_INTERVAL}s ...")
    else:
        print(f"R-Act (reactive): watching {REPORT_PATH} every {WATCH_INTERVAL}s ...")

    seen: set[str] = set()
    last_mtime: float = 0.0

    # Gather context once at startup (re-gathered on each new-report cycle)
    context_text = ""

    while True:
        report_available = False

        if remote:
            if _pull_from_target(REMOTE_REPORT_PATH):
                changed, last_mtime = _report_changed(LOCAL_CACHE, last_mtime)
                if changed:
                    report_available = True
                    local_path = LOCAL_CACHE
            # else: target not reachable yet -- keep polling silently
        else:
            if os.path.exists(REPORT_PATH):
                changed, last_mtime = _report_changed(REPORT_PATH, last_mtime)
                if changed:
                    report_available = True
                    local_path = REPORT_PATH

        if report_available:
            print(f"\n[R-Act] New report detected -- gathering server context ...")
            ctx = context_collector.gather()
            context_text = context_collector.format_for_prompt(ctx)

            try:
                findings = parse_trivy(local_path)
            except Exception as e:
                print(f"  report parse error: {e}")
                time.sleep(WATCH_INTERVAL)
                continue

            new = [f for f in findings
                   if f"{f['cve']}:{f['package']}" not in seen]
            if new:
                print(f"[R-Act] {len(new)} new finding(s) to process.")
                for f in new:
                    seen.add(f"{f['cve']}:{f['package']}")
                    handle(f, "R-Act", context_text)
            else:
                print("[R-Act] No new findings since last check.")

        time.sleep(WATCH_INTERVAL)


if __name__ == "__main__":
    main()
