"""
Interactive vulnerability remediation dashboard.

Parses the latest Trivy JSON + analysis markdown, generates LLM remediation
plans per finding in a background thread, and serves a rich UI on
http://localhost:8080 with per-finding action buttons.

GET  /            HTML dashboard
GET  /api/plans   Return plan generation status (polled by JS every 2 s)
POST /api/act     {cve, package, action: remediate|defer|skip} -> {ok, message}

Usage:
    python view_report.py                       # uses sample_report.json + latest report
    python view_report.py /path/to/scan.json    # specific Trivy JSON
"""
import datetime
import glob
import json
import os
import re
import sys
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Timer

HERE = Path(__file__).parent
(HERE / "reports").mkdir(exist_ok=True)

from config import TARGET_HOST, DRY_RUN
from remediation_core import make_plan, validate_plan, execute, audit

PORT = int(os.getenv("DASHBOARD_PORT", "8080"))
STATE_FILE = HERE / "reports" / "dashboard_state.json"

# ---------------------------------------------------------------------------
# Global state (thread-safe via _lock)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_findings: list[dict] = []
_plans: dict[str, object] = {}     # key -> plan dict | {"error": str} | "__pending__"
_status: dict[str, str] = {}       # key -> pending|remediated|deferred|skipped
_analysis: dict[str, str] = {}     # cve -> markdown text for that CVE
_meta: dict = {}                   # target, generated, total, critical, high, fixable


def _key(cve: str, pkg: str) -> str:
    return f"{cve}:{pkg}"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _find_trivy_json(arg: str = "") -> str:
    if arg and os.path.exists(arg):
        return arg
    default = HERE / "sample_report.json"
    if default.exists():
        return str(default)
    sys.exit("No Trivy JSON found. Pass the path as an argument or ensure sample_report.json exists.")


def _find_latest_md() -> str:
    files = sorted(glob.glob(str(HERE / "reports" / "vuln_analysis_*.md")))
    return files[-1] if files else ""


def _parse_trivy(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            if v.get("Severity") in ("HIGH", "CRITICAL"):
                findings.append({
                    "cve":       v.get("VulnerabilityID", ""),
                    "package":   v.get("PkgName", ""),
                    "installed": v.get("InstalledVersion", ""),
                    "fixed":     v.get("FixedVersion", ""),
                    "severity":  v.get("Severity", ""),
                    "title":     v.get("Title", ""),
                    "os_target": result.get("Target", ""),
                })
    findings.sort(key=lambda f: (0 if f["severity"] == "CRITICAL" else 1, f["cve"]))
    return findings


def _parse_md(path: str) -> tuple[dict, dict]:
    """Returns (meta_dict, {cve: analysis_markdown})."""
    if not path or not os.path.exists(path):
        return {}, {}
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    def grab(pattern, default=""):
        m = re.search(pattern, text)
        return m.group(1).strip() if m else default

    meta = {
        "target":    grab(r"\*\*Target:\*\*\s*(.+)"),
        "generated": grab(r"\*\*Generated:\*\*\s*(.+)"),
        "total":     grab(r"\*\*Total HIGH/CRITICAL findings:\*\*\s*(\d+)", "0"),
        "critical":  grab(r"\*\*Critical:\*\*\s*(\d+)", "0"),
        "high":      grab(r"\*\*High:\*\*\s*(\d+)", "0"),
        "fixable":   grab(r"\*\*Fixes available.*?:\*\*\s*(\d+)", "0"),
    }

    # Per-CVE: split on `### CVE-` headers
    cve_analysis: dict[str, str] = {}
    parts = re.split(r"###\s+(CVE-[\w-]+[^\n]*)\n", text)
    for i in range(1, len(parts), 2):
        cve_id_raw = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        cve_match = re.match(r"(CVE-[\d-]+)", cve_id_raw)
        if cve_match:
            # Trim at next ## section
            body = re.split(r"\n## ", body)[0].strip()
            cve_analysis[cve_match.group(1)] = body

    return meta, cve_analysis


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def _load_state() -> None:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            _status.update(data)
        except Exception:
            pass


def _save_state() -> None:
    STATE_FILE.write_text(json.dumps(_status, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Plan generation  (parallel, synchronous — all plans ready before page load)
# ---------------------------------------------------------------------------

def _generate_all_plans() -> None:
    """Call make_plan() for all findings in parallel; populate _plans."""

    def _one(f: dict) -> tuple[str, object]:
        k = _key(f["cve"], f["package"])
        if _status.get(k) in ("remediated", "deferred", "skipped"):
            return k, {"skipped": True}
        try:
            plan = make_plan(f)
            ok, why = validate_plan(plan, f)
            return k, (plan if ok else {"error": f"Validation failed: {why}"})
        except Exception as e:
            return k, {"error": str(e)}

    workers = min(len(_findings), 5)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_one, f): f for f in _findings}
        for fut in as_completed(futures):
            k, result = fut.result()
            with _lock:
                _plans[k] = result
            cve = k.split(":")[0]
            ok_flag = "ok" if not isinstance(result, dict) or not result.get("error") else "error"
            print(f"  plan {ok_flag}: {cve}")


# ---------------------------------------------------------------------------
# Markdown → HTML (inline only, used for analysis text in cards)
# ---------------------------------------------------------------------------

def _md_inline(t: str) -> str:
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"\*(.+?)\*",     r"<em>\1</em>",         t)
    t = re.sub(r"`(.+?)`",       r"<code>\1</code>",     t)
    return t


def _md_to_html(md: str) -> str:
    lines, out, in_list = md.splitlines(), [], False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    for raw in lines:
        line = raw.strip()
        if not line:
            close_list()
            continue
        m = re.match(r"[-*]\s+(.*)", line)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_md_inline(m.group(1))}</li>")
            continue
        close_list()
        out.append(f"<p>{_md_inline(line)}</p>")
    close_list()
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML page (single self-contained file, data embedded as JSON)
# ---------------------------------------------------------------------------

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Remediation Dashboard</title>
<style>
:root {
  --bg:       #f5f5f3;
  --surface:  #ffffff;
  --raised:   #f0efec;
  --inset:    #e8e7e3;
  --border:   #dddcd6;
  --ink:      #111110;
  --ink2:     #4a4946;
  --ink3:     #8a8885;
  --code:     #1d5fa8;
  --c-crit:   #c92c2c;
  --c-critbg: #fde8e8;
  --c-crittx: #7a1212;
  --c-high:   #a0420e;
  --c-highbg: #fdeadc;
  --c-hightx: #6b2500;
  --c-ok:     #1a6b1a;
  --c-okbg:   #e4f5e4;
  --c-okt:    #0d400d;
  --c-defer:  #7a6000;
  --c-defbg:  #fdf6d8;
  --c-deftx:  #4a3800;
  --c-skip:   #4a4946;
  --c-skipbg: #e8e7e3;
  --c-skiptx: #2a2925;
  --shadow:   0 1px 3px rgba(0,0,0,.08), 0 4px 12px rgba(0,0,0,.06);
  --rad:      10px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:       #161614;
    --surface:  #1e1e1c;
    --raised:   #252523;
    --inset:    #2c2c29;
    --border:   #363632;
    --ink:      #f0f0ed;
    --ink2:     #b8b7b0;
    --ink3:     #78776f;
    --code:     #6ab0f5;
    --c-crit:   #e05555;
    --c-critbg: #2a1010;
    --c-crittx: #f5a0a0;
    --c-high:   #d07040;
    --c-highbg: #241408;
    --c-hightx: #f5c49a;
    --c-ok:     #22a022;
    --c-okbg:   #0c1e0c;
    --c-okt:    #8fe88f;
    --c-defer:  #c4a800;
    --c-defbg:  #201c00;
    --c-deftx:  #f5e07a;
    --c-skip:   #78776f;
    --c-skipbg: #2c2c29;
    --c-skiptx: #c8c7c0;
  }
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink)}

/* ── HEADER ── */
.hdr{background:var(--surface);border-bottom:1px solid var(--border);padding:20px 32px}
.hdr-top{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.hdr h1{font-size:18px;font-weight:700;letter-spacing:-.02em;display:flex;align-items:center;gap:8px}
.hdr-meta{display:flex;gap:20px;flex-wrap:wrap;margin-top:8px;font-size:13px;color:var(--ink2)}
.hdr-meta span{display:flex;align-items:center;gap:5px}
.dry-badge{background:var(--c-defbg);color:var(--c-deftx);border:1px solid var(--c-defer);
  font-size:11px;font-weight:700;letter-spacing:.06em;padding:3px 10px;border-radius:20px}

/* ── STAT TILES ── */
.main{max-width:1160px;margin:0 auto;padding:24px 32px 60px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}
@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:var(--rad);padding:18px 20px}
.tile .lbl{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--ink3);margin-bottom:6px}
.tile .val{font-size:36px;font-weight:800;line-height:1;letter-spacing:-.03em}
.tile.crit .val{color:var(--c-crit)}
.tile.high .val{color:var(--c-high)}
.tile.ok   .val{color:var(--c-ok)}
.tile.def  .val{color:var(--c-defer)}
.tile.skip .val{color:var(--c-skip)}

/* ── CARDS ── */
.cards{display:flex;flex-direction:column;gap:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--rad);
  box-shadow:var(--shadow);overflow:hidden;transition:opacity .3s}
.card[data-status="remediated"]{opacity:.6}
.card[data-status="skipped"]{opacity:.5}

/* card header */
.card-hdr{display:flex;align-items:flex-start;justify-content:space-between;
  flex-wrap:wrap;gap:8px;padding:16px 20px;border-bottom:1px solid var(--border)}
.card-hdr.sev-critical{border-left:4px solid var(--c-crit)}
.card-hdr.sev-high    {border-left:4px solid var(--c-high)}
.hdr-left{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.hdr-right{display:flex;align-items:center;gap:8px;flex-shrink:0}
.sev-badge{font-size:11px;font-weight:800;letter-spacing:.07em;padding:3px 10px;
  border-radius:20px;white-space:nowrap}
.sev-badge.critical{background:var(--c-critbg);color:var(--c-crittx);border:1px solid var(--c-crit)}
.sev-badge.high    {background:var(--c-highbg);color:var(--c-hightx);border:1px solid var(--c-high)}
.cve-id{font-family:monospace;font-size:14px;font-weight:700;color:var(--code)}
.cve-title{font-size:13px;color:var(--ink2)}
.server-tag{font-size:12px;color:var(--ink3);background:var(--raised);
  border:1px solid var(--border);border-radius:6px;padding:2px 8px}
.status-pill{font-size:11px;font-weight:700;letter-spacing:.05em;padding:3px 10px;
  border-radius:20px;white-space:nowrap}
.status-pill.pending   {background:var(--raised);color:var(--ink3);border:1px solid var(--border)}
.status-pill.remediated{background:var(--c-okbg);color:var(--c-okt);border:1px solid var(--c-ok)}
.status-pill.deferred  {background:var(--c-defbg);color:var(--c-deftx);border:1px solid var(--c-defer)}
.status-pill.skipped   {background:var(--c-skipbg);color:var(--c-skiptx);border:1px solid var(--border)}

/* card body — 3 columns */
.card-body{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0;border-bottom:1px solid var(--border)}
@media(max-width:860px){.card-body{grid-template-columns:1fr}}
.col{padding:18px 20px;border-right:1px solid var(--border)}
.col:last-child{border-right:none}
@media(max-width:860px){.col{border-right:none;border-bottom:1px solid var(--border)}}
.col:last-child{border-bottom:none}
.col-title{font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ink3);margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}

/* detail rows */
.detail-row{display:flex;gap:8px;margin-bottom:7px;font-size:13px}
.detail-row dt{flex-shrink:0;width:90px;color:var(--ink3);font-weight:600}
.detail-row dd{color:var(--ink2);word-break:break-word}
.detail-row dd code{font-family:monospace;font-size:12px;color:var(--code)}
.detail-row dd.fixed{color:var(--c-ok);font-family:monospace;font-size:12px;font-weight:700}
.detail-row dd.nofix{color:var(--ink3);font-style:italic;font-size:12px}

/* analysis text */
.analysis-text p{font-size:13px;color:var(--ink2);margin-bottom:8px;line-height:1.55}
.analysis-text p:last-child{margin-bottom:0}
.analysis-text ul{padding-left:16px;margin-bottom:8px}
.analysis-text li{font-size:13px;color:var(--ink2);margin-bottom:4px}
.analysis-text strong{color:var(--ink)}
.analysis-text code{font-family:monospace;font-size:12px;background:var(--inset);
  border:1px solid var(--border);border-radius:3px;padding:1px 4px;color:var(--code)}
.no-analysis{font-size:13px;color:var(--ink3);font-style:italic}

/* plan section */
.plan-loading{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--ink3)}
.spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--ink3);
  border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.plan-error{font-size:12px;color:var(--c-crit);background:var(--c-critbg);
  border:1px solid var(--c-crit);border-radius:6px;padding:8px 10px}
.restore-box{margin-top:12px;background:var(--raised);border:1px solid var(--border);
  border-radius:6px;padding:10px 12px}
.restore-box .restore-lbl{font-size:10px;font-weight:800;letter-spacing:.08em;
  text-transform:uppercase;color:var(--ink3);margin-bottom:6px}
.restore-box p{font-size:12px;color:var(--ink2);line-height:1.5}

/* card footer buttons */
.card-footer{display:flex;gap:10px;padding:14px 20px;flex-wrap:wrap;background:var(--raised)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:7px;
  font-size:13px;font-weight:600;border:none;cursor:pointer;transition:all .15s;white-space:nowrap}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn-remediate{background:var(--c-ok);color:#fff}
.btn-remediate:hover:not(:disabled){filter:brightness(1.1)}
.btn-defer{background:var(--c-defbg);color:var(--c-deftx);border:1px solid var(--c-defer)}
.btn-defer:hover:not(:disabled){background:var(--c-defer);color:#fff}
.btn-skip{background:var(--c-skipbg);color:var(--c-skiptx);border:1px solid var(--border)}
.btn-skip:hover:not(:disabled){background:var(--inset)}
.btn-cancel{background:var(--raised);color:var(--ink2);border:1px solid var(--border)}
.btn-cancel:hover{background:var(--inset)}

/* ── MODAL ── */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;
  align-items:center;justify-content:center;z-index:100;padding:20px}
.modal-overlay.hidden{display:none}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:var(--rad);
  box-shadow:0 20px 60px rgba(0,0,0,.25);max-width:560px;width:100%;padding:28px}
.modal h2{font-size:16px;font-weight:700;margin-bottom:6px}
.modal .modal-sub{font-size:13px;color:var(--ink3);margin-bottom:20px}
.modal-section{margin-bottom:16px}
.modal-section-title{font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ink3);margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.modal .detail-row{margin-bottom:6px}
.modal-footer{display:flex;gap:10px;margin-top:22px;flex-wrap:wrap}

/* ── TOAST ── */
#toasts{position:fixed;bottom:24px;right:24px;display:flex;flex-direction:column;gap:8px;z-index:200}
.toast{background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:12px 18px;font-size:13px;font-weight:500;box-shadow:var(--shadow);
  animation:slide-up .25s ease;max-width:320px}
.toast.success{border-left:4px solid var(--c-ok)}
.toast.error  {border-left:4px solid var(--c-crit)}
.toast.info   {border-left:4px solid var(--c-defer)}
@keyframes slide-up{from{transform:translateY(10px);opacity:0}to{transform:translateY(0);opacity:1}}
</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-top">
    <h1>&#128274; Vulnerability Remediation Dashboard</h1>
    __DRY_RUN_BADGE__
  </div>
  <div class="hdr-meta">
    <span>&#128187; <strong>Server:</strong>&nbsp;__SERVER__</span>
    <span>&#128197; <strong>Scan:</strong>&nbsp;__GENERATED__</span>
    <span>&#128196; <strong>Source:</strong>&nbsp;__SOURCE__</span>
  </div>
</header>

<main class="main">
  <div class="stats" id="stats"></div>
  <div class="cards" id="cards"></div>
</main>

<div class="modal-overlay hidden" id="modal">
  <div class="modal">
    <h2 id="modal-title">Confirm Remediation</h2>
    <div class="modal-sub" id="modal-sub"></div>
    <div id="modal-body"></div>
    <div class="modal-footer">
      <button class="btn btn-remediate" id="modal-confirm" onclick="confirmRemediate()">&#9654; Confirm Patch</button>
      <button class="btn btn-cancel" onclick="closeModal()">Cancel</button>
    </div>
  </div>
</div>

<div id="toasts"></div>

<script>
const FINDINGS = __FINDINGS_JSON__;
const STATUS   = __STATUS_JSON__;
const META     = __META_JSON__;
const ANALYSIS = __ANALYSIS_JSON__;

let plans  = __PLANS_JSON__;
let status = Object.assign({}, STATUS);
let pendingAction = null;

const SEV_ORDER = {CRITICAL: 0, HIGH: 1};

function key(cve, pkg) { return cve + ":" + pkg; }

/* ── Stats ── */
function renderStats() {
  const counts = {total: 0, critical: 0, high: 0, deferred: 0, skipped: 0, remediated: 0};
  FINDINGS.forEach(f => {
    const k = key(f.cve, f.package);
    counts.total++;
    if (f.severity === "CRITICAL") counts.critical++;
    else if (f.severity === "HIGH") counts.high++;
    const s = status[k] || "pending";
    if (s === "remediated") counts.remediated++;
    if (s === "deferred")   counts.deferred++;
    if (s === "skipped")    counts.skipped++;
  });
  document.getElementById("stats").innerHTML = `
    <div class="tile"><div class="lbl">Total</div><div class="val">${counts.total}</div></div>
    <div class="tile crit"><div class="lbl">&#9888; Critical</div><div class="val">${counts.critical}</div></div>
    <div class="tile high"><div class="lbl">&#9888; High</div><div class="val">${counts.high}</div></div>
    <div class="tile ok"><div class="lbl">&#10003; Remediated</div><div class="val">${counts.remediated}</div></div>
    <div class="tile def"><div class="lbl">&#9208; Deferred</div><div class="val">${counts.deferred}</div></div>`;
}

/* ── Plan HTML ── */
function planHtml(k, f) {
  const p = plans[k];
  if (!p) return `<div class="plan-loading"><div class="spinner"></div>Generating plan&hellip;</div>`;
  if (p.error) return `<div class="plan-error">&#9888; ${escHtml(p.error)}</div>`;
  if (p.skipped) return `<div class="no-analysis">Decision already recorded.</div>`;
  const restarts = (p.services_to_restart||[]).join(", ") || "none";
  const reboot   = p.reboot_required ? "Yes" : "No";
  return `
    <dl>
      <div class="detail-row"><dt>Action</dt><dd>${escHtml(p.action||"")}</dd></div>
      <div class="detail-row"><dt>Restart</dt><dd>${escHtml(restarts)}</dd></div>
      <div class="detail-row"><dt>Reboot</dt><dd>${reboot}</dd></div>
      <div class="detail-row"><dt>Reason</dt><dd>${escHtml(p.reason||"")}</dd></div>
    </dl>
    ${p.restore_plan ? `<div class="restore-box">
      <div class="restore-lbl">&#9889; Restoration Plan (auto if smoke test fails)</div>
      <p>${escHtml(p.restore_plan)}</p>
    </div>` : ""}`;
}

/* ── Card HTML ── */
function cardHtml(f) {
  const k   = key(f.cve, f.package);
  const st  = status[k] || "pending";
  const sev = f.severity.toLowerCase();
  const stLabels = {pending:"Pending", remediated:"&#10003; Remediated",
                    deferred:"&#9208; Deferred", skipped:"&#215; Not Remediated"};
  const an = ANALYSIS[f.cve] || "";
  const disabled = (st !== "pending") ? " disabled" : "";
  return `
<div class="card" id="card-${k}" data-key="${k}" data-status="${st}">
  <div class="card-hdr sev-${sev}">
    <div class="hdr-left">
      <span class="sev-badge ${sev}">${f.severity}</span>
      <span class="cve-id">${escHtml(f.cve)}</span>
      <span class="cve-title">${escHtml(f.title)}</span>
    </div>
    <div class="hdr-right">
      <span class="server-tag">&#128187; ${escHtml(META.target||"target-node01")}</span>
      <span class="status-pill ${st}" id="pill-${k}">${stLabels[st]||st}</span>
    </div>
  </div>

  <div class="card-body">
    <div class="col">
      <div class="col-title">&#128196; Technical Details</div>
      <dl>
        <div class="detail-row"><dt>Package</dt><dd><strong>${escHtml(f.package)}</strong></dd></div>
        <div class="detail-row"><dt>Installed</dt><dd><code>${escHtml(f.installed)}</code></dd></div>
        <div class="detail-row"><dt>Fixed</dt><dd class="${f.fixed ? "fixed":"nofix"}">${f.fixed ? escHtml(f.fixed) : "No fix available"}</dd></div>
        <div class="detail-row"><dt>OS / Target</dt><dd>${escHtml(f.os_target)}</dd></div>
        <div class="detail-row"><dt>Severity</dt><dd>${escHtml(f.severity)}</dd></div>
      </dl>
    </div>

    <div class="col">
      <div class="col-title">&#129302; Agent Analysis</div>
      <div class="analysis-text" id="analysis-${k}">
        ${an ? mdToHtml(an) : '<span class="no-analysis">Run analyze.py to generate analysis.</span>'}
      </div>
    </div>

    <div class="col">
      <div class="col-title">&#128295; Remediation Plan</div>
      <div id="plan-${k}">${planHtml(k, f)}</div>
    </div>
  </div>

  <div class="card-footer">
    <button class="btn btn-remediate" id="btn-rem-${k}"${disabled}
      onclick="openRemediate('${escAttr(f.cve)}','${escAttr(f.package)}')">
      &#9654; Agent-Remediate
    </button>
    <button class="btn btn-defer" id="btn-def-${k}"${disabled}
      onclick="deferFinding('${escAttr(f.cve)}','${escAttr(f.package)}')">
      &#9208; Defer for Review
    </button>
    <button class="btn btn-skip" id="btn-skp-${k}"${disabled}
      onclick="skipFinding('${escAttr(f.cve)}','${escAttr(f.package)}')">
      &#215; Not Remediate
    </button>
  </div>
</div>`;
}

/* ── Render all cards ── */
function renderCards() {
  document.getElementById("cards").innerHTML = FINDINGS.map(cardHtml).join("\n");
}

/* ── Modal ── */
function openRemediate(cve, pkg) {
  const k = key(cve, pkg);
  const p = plans[k];
  if (!p) { showToast("Plan not ready yet — please wait a moment.", "info"); return; }
  if (p.error) { showToast("Plan error: " + p.error, "error"); return; }
  const f = FINDINGS.find(x => x.cve===cve && x.package===pkg) || {};
  pendingAction = {cve, pkg};
  const restarts = (p.services_to_restart||[]).join(", ") || "none";
  document.getElementById("modal-title").textContent = "Confirm Patch: " + cve;
  document.getElementById("modal-sub").textContent =
    f.package + "  " + (f.installed||"") + " → " + (f.fixed||"latest");
  document.getElementById("modal-body").innerHTML = `
    <div class="modal-section">
      <div class="modal-section-title">&#128196; Remediation Plan</div>
      <dl>
        <div class="detail-row"><dt>Action</dt><dd>${escHtml(p.action||"")}</dd></div>
        <div class="detail-row"><dt>Package</dt><dd><code>${escHtml(pkg)}</code></dd></div>
        <div class="detail-row"><dt>Restart</dt><dd>${escHtml(restarts)}</dd></div>
        <div class="detail-row"><dt>Reboot</dt><dd>${p.reboot_required?"Yes":"No"}</dd></div>
        <div class="detail-row"><dt>Reason</dt><dd>${escHtml(p.reason||"")}</dd></div>
      </dl>
    </div>
    ${p.restore_plan ? `<div class="modal-section">
      <div class="modal-section-title">&#9889; Restoration Plan (automatic on smoke-test failure)</div>
      <p style="font-size:13px;color:var(--ink2)">${escHtml(p.restore_plan)}</p>
    </div>` : ""}`;
  document.getElementById("modal").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("modal").classList.add("hidden");
  pendingAction = null;
}

async function confirmRemediate() {
  if (!pendingAction) return;
  const {cve, pkg} = pendingAction;
  closeModal();
  setButtons(key(cve,pkg), true);
  const resp = await postAct(cve, pkg, "remediate");
  if (resp.ok) {
    updateStatus(key(cve,pkg), "remediated");
    showToast("&#10003; Remediated: " + cve, "success");
  } else {
    setButtons(key(cve,pkg), false);
    showToast("&#9888; " + (resp.message||"Unknown error"), "error");
  }
}

/* ── Defer / Skip ── */
async function deferFinding(cve, pkg) {
  const k = key(cve, pkg);
  setButtons(k, true);
  const resp = await postAct(cve, pkg, "defer");
  if (resp.ok) { updateStatus(k,"deferred"); showToast("&#9208; Deferred: "+cve,"info"); }
  else { setButtons(k,false); showToast("Error: "+(resp.message||""),"error"); }
}

async function skipFinding(cve, pkg) {
  const k = key(cve, pkg);
  setButtons(k, true);
  const resp = await postAct(cve, pkg, "skip");
  if (resp.ok) { updateStatus(k,"skipped"); showToast("&#215; Skipped: "+cve,"info"); }
  else { setButtons(k,false); showToast("Error: "+(resp.message||""),"error"); }
}

/* ── API ── */
async function postAct(cve, pkg, action) {
  try {
    const r = await fetch("/api/act", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({cve, package: pkg, action})
    });
    return await r.json();
  } catch(e) { return {ok:false, message: String(e)}; }
}

/* ── UI helpers ── */
function updateStatus(k, st) {
  status[k] = st;
  const stLabels = {pending:"Pending", remediated:"&#10003; Remediated",
                    deferred:"&#9208; Deferred", skipped:"&#215; Not Remediated"};
  const pill = document.getElementById("pill-"+k);
  if (pill) { pill.className="status-pill "+st; pill.innerHTML=stLabels[st]||st; }
  const card = document.getElementById("card-"+k);
  if (card) card.dataset.status = st;
  renderStats();
}

function setButtons(k, disabled) {
  ["btn-rem-","btn-def-","btn-skp-"].forEach(p => {
    const b = document.getElementById(p+k);
    if (b) b.disabled = disabled;
  });
}

function showToast(msg, type="info") {
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.innerHTML = msg;
  document.getElementById("toasts").appendChild(el);
  setTimeout(()=>el.remove(), 4000);
}

/* ── Poll /api/plans until all ready ── */
let _pollInterval = null;
function allPlansReady() {
  return FINDINGS.every(f => plans[key(f.cve,f.package)] !== undefined);
}

async function pollPlans() {
  try {
    const r = await fetch("/api/plans");
    const data = await r.json();
    let changed = false;
    Object.keys(data).forEach(k => {
      if (plans[k] === undefined && data[k] !== undefined) {
        plans[k] = data[k];
        const planDiv = document.getElementById("plan-"+k);
        const f = FINDINGS.find(x => key(x.cve,x.package)===k);
        if (planDiv && f) planDiv.innerHTML = planHtml(k, f);
        changed = true;
      }
    });
    if (allPlansReady() && _pollInterval) {
      clearInterval(_pollInterval);
      _pollInterval = null;
    }
  } catch(e) {}
}

/* ── Minimal markdown → HTML (for analysis text) ── */
function mdToHtml(md) {
  if (!md) return "";
  const lines = md.split("\n");
  let html = "", inList = false;
  lines.forEach(raw => {
    const line = raw.trim();
    if (!line) { if (inList) { html += "</ul>"; inList=false; } return; }
    const li = line.match(/^[-*]\s+(.*)/);
    if (li) {
      if (!inList) { html += "<ul>"; inList=true; }
      html += "<li>" + inlineHtml(li[1]) + "</li>";
      return;
    }
    if (inList) { html += "</ul>"; inList=false; }
    html += "<p>" + inlineHtml(line) + "</p>";
  });
  if (inList) html += "</ul>";
  return html;
}

function inlineHtml(t) {
  return t.replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>")
          .replace(/\*(.+?)\*/g,"<em>$1</em>")
          .replace(/`(.+?)`/g,"<code>$1</code>")
          .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
// Override to avoid double-escaping (inlineHtml already handles basic cases)
function inlineHtml(t) {
  return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
          .replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>")
          .replace(/\*(.+?)\*/g,"<em>$1</em>")
          .replace(/`(.+?)`/g,"<code>$1</code>");
}

function escHtml(s) {
  return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function escAttr(s) {
  return String(s||"").replace(/'/g,"\\'");
}

/* ── Init ── */
renderStats();
renderCards();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):

    def log_message(self, *_):
        pass  # silence per-request noise

    # ── GET ─────────────────────────────────────────────────────────────────

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_dashboard()
        elif self.path == "/api/plans":
            self._serve_plans()
        else:
            self.send_error(404)

    def _serve_dashboard(self):
        html = _render_html()
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_plans(self):
        with _lock:
            data = {k: v for k, v in _plans.items()}
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── POST ────────────────────────────────────────────────────────────────

    def do_POST(self):
        if self.path != "/api/act":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length))
        except Exception:
            self._json_response(400, {"ok": False, "message": "Invalid JSON"})
            return

        cve    = payload.get("cve", "")
        pkg    = payload.get("package", "")
        action = payload.get("action", "")
        k      = _key(cve, pkg)

        if action == "defer":
            with _lock:
                _status[k] = "deferred"
            _save_state()
            self._json_response(200, {"ok": True, "message": "Deferred", "status": "deferred"})
            return

        if action == "skip":
            with _lock:
                _status[k] = "skipped"
            _save_state()
            self._json_response(200, {"ok": True, "message": "Skipped", "status": "skipped"})
            return

        if action == "remediate":
            with _lock:
                plan = _plans.get(k)
            if plan is None:
                self._json_response(202, {"ok": False, "message": "Plan not ready yet — please wait."})
                return
            if isinstance(plan, dict) and plan.get("error"):
                self._json_response(400, {"ok": False, "message": plan["error"]})
                return
            finding = next((f for f in _findings if f["cve"] == cve and f["package"] == pkg), None)
            if not finding:
                self._json_response(404, {"ok": False, "message": "Finding not found"})
                return
            try:
                rc = execute(plan)
                st = "remediated" if rc == 0 else "failed"
                audit("dashboard", finding, plan, st)
                with _lock:
                    _status[k] = "remediated" if rc == 0 else "pending"
                if rc == 0:
                    _save_state()
                    self._json_response(200, {"ok": True, "message": "Remediation complete", "status": "remediated"})
                else:
                    self._json_response(500, {"ok": False, "message": "Ansible failed — rolled back. Check audit.log."})
            except Exception as e:
                self._json_response(500, {"ok": False, "message": str(e)})
            return

        self._json_response(400, {"ok": False, "message": f"Unknown action: {action}"})

    def _json_response(self, code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def _render_html() -> str:
    with _lock:
        findings_snap = list(_findings)
        plans_snap    = {k: v for k, v in _plans.items()}
        status_snap   = dict(_status)
        analysis_snap = dict(_analysis)
        meta_snap     = dict(_meta)

    # Initialise pending slots for findings not yet generated
    for f in findings_snap:
        k = _key(f["cve"], f["package"])
        if k not in plans_snap:
            plans_snap[k] = None  # JS sees null → loading state

    dry_badge = ('<span class="dry-badge">DRY RUN</span>' if DRY_RUN else "")

    return (_HTML
        .replace("__DRY_RUN_BADGE__", dry_badge)
        .replace("__SERVER__",     _esc(meta_snap.get("target", TARGET_HOST)))
        .replace("__GENERATED__",  _esc(meta_snap.get("generated", "unknown")))
        .replace("__SOURCE__",     _esc(meta_snap.get("source", "")))
        .replace("__FINDINGS_JSON__", json.dumps(findings_snap))
        .replace("__PLANS_JSON__",    json.dumps(plans_snap))
        .replace("__STATUS_JSON__",   json.dumps(status_snap))
        .replace("__ANALYSIS_JSON__", json.dumps(analysis_snap))
        .replace("__META_JSON__",     json.dumps(meta_snap))
    )


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global _findings, _meta, _analysis

    trivy_path = sys.argv[1] if len(sys.argv) > 1 else _find_trivy_json()
    md_path    = _find_latest_md()

    print(f"Trivy JSON : {trivy_path}")
    if md_path:
        print(f"Analysis  : {md_path}")
    else:
        print("Analysis  : (none — run analyze.py to generate)")

    _findings = _parse_trivy(trivy_path)
    if not _findings:
        sys.exit("No HIGH/CRITICAL findings in the report.")

    meta, analysis = _parse_md(md_path)
    meta["source"] = os.path.basename(trivy_path)
    if not meta.get("target"):
        meta["target"] = TARGET_HOST
    if not meta.get("generated"):
        meta["generated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    _meta.update(meta)
    _analysis.update(analysis)

    for f in _findings:
        _status.setdefault(_key(f["cve"], f["package"]), "pending")

    _load_state()

    print(f"Findings  : {len(_findings)}  ({meta.get('critical','?')} critical, {meta.get('high','?')} high)")
    print(f"Dry run   : {'YES (set DRY_RUN=0 on the control node)' if DRY_RUN else 'NO — real patching'}")

    print(f"Plans     : generating {len(_findings)} plan(s) via LLM (parallel)…")
    _generate_all_plans()
    print(f"Plans     : all ready — {len(_plans)} plan(s) generated.")

    url = f"http://localhost:{PORT}"
    print(f"\nDashboard : {url}  (Ctrl+C to stop)\n")

    Timer(0.6, lambda: webbrowser.open(url)).start()

    with HTTPServer(("127.0.0.1", PORT), _Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
