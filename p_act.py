"""P-Act - PROACTIVE agent.

Trigger: its own schedule. P-Act initiates a Trivy scan of the target on a
fixed cadence (SCAN_INTERVAL), gathers server context, finds HIGH/CRITICAL
issues before any routine report would surface them, and runs the shared
remediation pipeline (with user approval).

The ONLY real difference from R-Act is the trigger (schedule vs. file event).
"""
import os
import subprocess
import tempfile
import time

import context_collector
from config import (JUMP_HOST, SCAN_INTERVAL, SSH_USER, TARGET_HOST,
                    TRIVY_PATH, ssh_opts)
from remediation_core import handle, parse_trivy

LOCAL_REPORT = os.path.join(tempfile.gettempdir(), "p_act_scan.json")
REMOTE_SCAN  = (
    f"sudo {TRIVY_PATH} rootfs --scanners vuln --pkg-types os "
    "--severity HIGH,CRITICAL --timeout 15m --quiet --format json "
    "-o /tmp/p_scan.json /"
)


def scan() -> bool:
    """SSH to target, run Trivy, pull the report. Returns True on success."""
    r1 = subprocess.run(
        ["ssh"] + ssh_opts() + [f"{SSH_USER}@{TARGET_HOST}", REMOTE_SCAN],
        check=False,
    )
    if r1.returncode != 0:
        print("  [P-Act] Trivy scan failed or target unreachable.")
        return False
    r2 = subprocess.run(
        ["scp"] + ssh_opts() +
        [f"{SSH_USER}@{TARGET_HOST}:/tmp/p_scan.json", LOCAL_REPORT],
        check=False,
    )
    return r2.returncode == 0


def main() -> None:
    print(f"P-Act (proactive): scanning {TARGET_HOST} every {SCAN_INTERVAL}s ...")
    while True:
        print(f"\n[P-Act] Starting scan cycle ...")
        if scan() and os.path.exists(LOCAL_REPORT):
            print("[P-Act] Scan complete. Gathering server context ...")
            ctx = context_collector.gather()
            context_text = context_collector.format_for_prompt(ctx)

            findings = parse_trivy(LOCAL_REPORT)
            if findings:
                for f in findings:
                    handle(f, "P-Act", context_text)
            else:
                print("[P-Act] No HIGH/CRITICAL findings.")
        else:
            print("[P-Act] Scan failed or produced no report.")

        print(f"[P-Act] Cycle complete; sleeping {SCAN_INTERVAL}s ...")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
