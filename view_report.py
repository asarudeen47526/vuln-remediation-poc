"""
view_report.py  --  Render the latest vuln analysis report as an HTML dashboard
                    and serve it on http://localhost:8080

Usage:
    python view_report.py                   # picks the newest reports/*.md
    python view_report.py reports/foo.md    # specific report
"""
import glob
import http.server
import os
import re
import sys
import webbrowser
from threading import Timer

# ---------------------------------------------------------------------------
# 1. Find & parse the markdown report
# ---------------------------------------------------------------------------

def latest_report() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    pattern = os.path.join(here, "reports", "vuln_analysis_*.md")
    files = sorted(glob.glob(pattern))
    if not files:
        sys.exit("No reports found in reports/. Run: python analyze.py sample_report.json")
    return files[-1]


def parse_report(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    def grab(pattern, default=""):
        m = re.search(pattern, text)
        return m.group(1).strip() if m else default

    target    = grab(r"\*\*Target:\*\*\s*(.+)")
    generated = grab(r"\*\*Generated:\*\*\s*(.+)")
    total     = grab(r"\*\*Total HIGH/CRITICAL findings:\*\*\s*(\d+)", "0")
    critical  = grab(r"\*\*Critical:\*\*\s*(\d+)", "0")
    high      = grab(r"\*\*High:\*\*\s*(\d+)", "0")
    fixable   = grab(r"\*\*Fixes available.*?:\*\*\s*(\d+)", "0")

    # Analyst assessment: everything between "## Analyst assessment" and "## All findings"
    m = re.search(r"## Analyst assessment\s*\n(.*?)\n## All findings", text, re.DOTALL)
    assessment_md = m.group(1).strip() if m else ""

    # All findings table rows
    findings = []
    table_block = re.search(r"## All findings.*?(\|.*)", text, re.DOTALL)
    if table_block:
        for line in table_block.group(1).splitlines():
            line = line.strip()
            if not line.startswith("|") or re.match(r"\|[-| ]+\|", line):
                continue
            cols = [c.strip() for c in line.strip("|").split("|")]
            if len(cols) >= 5 and cols[0] != "CVE":
                findings.append({
                    "cve":       cols[0],
                    "package":   cols[1],
                    "severity":  cols[2],
                    "installed": cols[3],
                    "fixed":     cols[4] if cols[4] not in ("", "-", "—") else None,
                })

    return dict(target=target, generated=generated, total=total, critical=critical,
                high=high, fixable=fixable, assessment_md=assessment_md, findings=findings,
                source_file=os.path.basename(path))


# ---------------------------------------------------------------------------
# 2. Minimal markdown-to-HTML (handles the LLM assessment output)
# ---------------------------------------------------------------------------

def _inline(text: str) -> str:
    """Convert inline markdown marks to HTML."""
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*",     r"<em>\1</em>",         text)
    text = re.sub(r"`(.+?)`",       r"<code>\1</code>",     text)
    return text


def md_to_html(md: str) -> str:
    lines = md.splitlines()
    out = []
    i = 0
    in_list = False
    in_table = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def close_table():
        nonlocal in_table
        if in_table:
            out.append("</tbody></table>")
            in_table = False

    while i < len(lines):
        raw = lines[i]
        line = raw.strip()

        # Blank line
        if not line:
            close_list()
            close_table()
            i += 1
            continue

        # ATX headings
        m = re.match(r"(#{1,4})\s+(.*)", line)
        if m:
            close_list(); close_table()
            level = len(m.group(1)) + 1  # bump: # in LLM output -> h2 in page
            level = min(level, 5)
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
            i += 1
            continue

        # Table row
        if line.startswith("|"):
            if re.match(r"\|[-| :]+\|", line):  # separator row
                i += 1
                continue
            cols = [c.strip() for c in line.strip("|").split("|")]
            if not in_table:
                close_list()
                # peek back: if the last appended line has <th> it was the header
                # otherwise start fresh
                if out and "<th>" in out[-1]:
                    out.append("<tbody>")
                    in_table = True
                else:
                    # header row
                    header = "".join(f"<th>{_inline(c)}</th>" for c in cols)
                    out.append(f'<table><thead><tr>{header}</tr></thead>')
                    in_table = False  # will be set after separator
                    # look for separator on next line
                    if i + 1 < len(lines) and re.match(r"\|[-| :]+\|", lines[i+1].strip()):
                        out.append("<tbody>")
                        in_table = True
                        i += 2
                        continue
            else:
                row = "".join(f"<td>{_inline(c)}</td>" for c in cols)
                out.append(f"<tr>{row}</tr>")
            i += 1
            continue

        # List item
        m = re.match(r"[-*+]\s+(.*)", line)
        if m:
            close_table()
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(m.group(1))}</li>")
            i += 1
            continue

        # Numbered list item
        m = re.match(r"\d+\.\s+(.*)", line)
        if m:
            close_table()
            if not in_list:
                out.append('<ul class="ordered">')
                in_list = True
            out.append(f"<li>{_inline(m.group(1))}</li>")
            i += 1
            continue

        # Regular paragraph text
        close_list(); close_table()
        out.append(f"<p>{_inline(line)}</p>")
        i += 1

    close_list()
    close_table()
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 3. Build the HTML dashboard
# ---------------------------------------------------------------------------

def severity_badge(sev: str) -> str:
    sev = sev.upper()
    if sev == "CRITICAL":
        return '<span class="badge badge-critical"><span aria-hidden="true">&#9888;</span> CRITICAL</span>'
    if sev == "HIGH":
        return '<span class="badge badge-high"><span aria-hidden="true">&#9888;</span> HIGH</span>'
    return f'<span class="badge badge-other">{sev}</span>'


def findings_rows(findings: list) -> str:
    rows = []
    for f in findings:
        fixed_cell = (f'<span class="fixed-version">{f["fixed"]}</span>'
                      if f["fixed"] else '<span class="no-fix">No fix yet</span>')
        rows.append(
            f'<tr>'
            f'<td><code class="cve">{f["cve"]}</code></td>'
            f'<td><strong>{f["package"]}</strong></td>'
            f'<td>{severity_badge(f["severity"])}</td>'
            f'<td><code>{f["installed"]}</code></td>'
            f'<td>{fixed_cell}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vulnerability Report &mdash; {target}</title>
  <style>
    /* ---- palette tokens ---- */
    :root {{
      --surface:          #fcfcfb;
      --surface-raised:   #f2f2ef;
      --surface-inset:    #eaeae6;
      --border:           #e1e0d9;
      --ink-primary:      #0b0b0b;
      --ink-secondary:    #52514e;
      --ink-muted:        #898781;
      --ink-code:         #256abf;
      --status-critical:        #d03b3b;
      --status-critical-bg:     #fce9e9;
      --status-critical-text:   #8c1a1a;
      --status-high:            #a84a1a;
      --status-high-bg:         #fdeee4;
      --status-high-text:       #7a2e08;
      --status-good:            #006300;
      --status-good-bg:         #e6f5e6;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --surface:          #1a1a19;
        --surface-raised:   #242422;
        --surface-inset:    #2c2c2a;
        --border:           #2c2c2a;
        --ink-primary:      #ffffff;
        --ink-secondary:    #c3c2b7;
        --ink-muted:        #898781;
        --ink-code:         #6da7ec;
        --status-critical:        #e66767;
        --status-critical-bg:     #2d1414;
        --status-critical-text:   #f5a0a0;
        --status-high:            #ec835a;
        --status-high-bg:         #2b1a0e;
        --status-high-text:       #f5b89a;
        --status-good:            #0ca30c;
        --status-good-bg:         #0d200d;
      }}
    }}

    /* ---- reset & base ---- */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
      background: var(--surface);
      color: var(--ink-primary);
      font-size: 15px;
      line-height: 1.6;
    }}

    /* ---- layout ---- */
    .page-header {{
      background: var(--surface-raised);
      border-bottom: 1px solid var(--border);
      padding: 24px 32px 20px;
    }}
    .page-header h1 {{
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .page-header h1 .icon {{ font-size: 22px; }}
    .page-header .meta {{
      margin-top: 6px;
      font-size: 13px;
      color: var(--ink-secondary);
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
    }}
    .page-header .meta span {{ display: flex; align-items: center; gap: 5px; }}

    .main {{ max-width: 1100px; margin: 0 auto; padding: 28px 32px 60px; }}

    /* ---- stat tiles ---- */
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 36px;
    }}
    @media (max-width: 700px) {{
      .stat-grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    .stat-tile {{
      background: var(--surface-raised);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px 22px;
    }}
    .stat-tile .label {{
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--ink-muted);
      margin-bottom: 8px;
    }}
    .stat-tile .value {{
      font-size: 40px;
      font-weight: 700;
      line-height: 1;
      letter-spacing: -0.03em;
    }}
    .stat-tile.critical .value {{ color: var(--status-critical); }}
    .stat-tile.high     .value {{ color: var(--status-high); }}
    .stat-tile.fixable  .value {{ color: var(--status-good); }}

    /* ---- section headings ---- */
    .section-heading {{
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.07em;
      text-transform: uppercase;
      color: var(--ink-muted);
      margin-bottom: 14px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }}

    /* ---- assessment prose ---- */
    .assessment {{
      background: var(--surface-raised);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px 28px;
      margin-bottom: 32px;
    }}
    .assessment h2, .assessment h3, .assessment h4, .assessment h5 {{
      margin-top: 20px;
      margin-bottom: 8px;
      font-size: 15px;
      font-weight: 700;
    }}
    .assessment h2:first-child {{ margin-top: 0; }}
    .assessment p {{ margin-bottom: 12px; color: var(--ink-secondary); }}
    .assessment p:last-child {{ margin-bottom: 0; }}
    .assessment ul, .assessment ul.ordered {{
      padding-left: 22px;
      margin-bottom: 12px;
      list-style: disc;
    }}
    .assessment ul.ordered {{ list-style: decimal; }}
    .assessment li {{ margin-bottom: 4px; color: var(--ink-secondary); }}
    .assessment code {{
      font-family: "SFMono-Regular", Consolas, "Courier New", monospace;
      font-size: 13px;
      background: var(--surface-inset);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 1px 5px;
      color: var(--ink-code);
    }}
    .assessment strong {{ color: var(--ink-primary); }}
    .assessment table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 16px;
      font-size: 14px;
    }}
    .assessment th {{
      text-align: left;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.04em;
      color: var(--ink-muted);
      padding: 8px 12px;
      border-bottom: 2px solid var(--border);
    }}
    .assessment td {{
      padding: 9px 12px;
      border-bottom: 1px solid var(--border);
      color: var(--ink-secondary);
      vertical-align: top;
    }}
    .assessment tr:last-child td {{ border-bottom: none; }}
    .assessment tr:hover td {{ background: var(--surface-inset); }}

    /* ---- findings table ---- */
    .findings-table-wrap {{
      background: var(--surface-raised);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }}
    .findings-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
      font-variant-numeric: tabular-nums;
    }}
    .findings-table thead th {{
      text-align: left;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.07em;
      text-transform: uppercase;
      color: var(--ink-muted);
      padding: 12px 16px;
      background: var(--surface-inset);
      border-bottom: 1px solid var(--border);
    }}
    .findings-table tbody td {{
      padding: 13px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }}
    .findings-table tbody tr:last-child td {{ border-bottom: none; }}
    .findings-table tbody tr:hover td {{ background: var(--surface-inset); }}

    code.cve {{
      font-family: "SFMono-Regular", Consolas, "Courier New", monospace;
      font-size: 13px;
      color: var(--ink-code);
    }}
    .findings-table code {{
      font-family: "SFMono-Regular", Consolas, "Courier New", monospace;
      font-size: 13px;
      color: var(--ink-muted);
    }}

    /* ---- severity badges ---- */
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
      padding: 3px 10px;
      border-radius: 20px;
      white-space: nowrap;
    }}
    .badge-critical {{
      background: var(--status-critical-bg);
      color: var(--status-critical-text);
      border: 1px solid var(--status-critical);
    }}
    .badge-high {{
      background: var(--status-high-bg);
      color: var(--status-high-text);
      border: 1px solid var(--status-high);
    }}
    .badge-other {{
      background: var(--surface-inset);
      color: var(--ink-secondary);
      border: 1px solid var(--border);
    }}

    .fixed-version {{
      font-family: "SFMono-Regular", Consolas, "Courier New", monospace;
      font-size: 13px;
      color: var(--status-good);
      font-weight: 600;
    }}
    .no-fix {{
      font-size: 13px;
      color: var(--ink-muted);
      font-style: italic;
    }}

    /* ---- footer ---- */
    .footer {{
      margin-top: 40px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      font-size: 12px;
      color: var(--ink-muted);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
    }}
  </style>
</head>
<body>
  <header class="page-header">
    <h1><span class="icon">&#128274;</span> Vulnerability Analysis Report</h1>
    <div class="meta">
      <span>&#x1F4BB; <strong>Target:</strong>&nbsp;{target}</span>
      <span>&#128337; <strong>Generated:</strong>&nbsp;{generated}</span>
      <span>&#128196; <strong>Source:</strong>&nbsp;{source_file}</span>
    </div>
  </header>

  <main class="main">

    <!-- Stat tiles -->
    <div class="stat-grid">
      <div class="stat-tile">
        <div class="label">Total findings</div>
        <div class="value">{total}</div>
      </div>
      <div class="stat-tile critical">
        <div class="label">&#9888; Critical</div>
        <div class="value">{critical}</div>
      </div>
      <div class="stat-tile high">
        <div class="label">&#9888; High</div>
        <div class="value">{high}</div>
      </div>
      <div class="stat-tile fixable">
        <div class="label">&#10003; Fixable</div>
        <div class="value">{fixable}</div>
      </div>
    </div>

    <!-- Analyst assessment -->
    <div class="section-heading">Analyst assessment</div>
    <div class="assessment">
      {assessment_html}
    </div>

    <!-- All findings -->
    <div class="section-heading" style="margin-top:32px">All findings</div>
    <div class="findings-table-wrap">
      <table class="findings-table">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Package</th>
            <th>Severity</th>
            <th>Installed</th>
            <th>Fixed version</th>
          </tr>
        </thead>
        <tbody>
          {findings_rows}
        </tbody>
      </table>
    </div>

    <div class="footer">
      <span>vuln-remediation-poc &mdash; analysis only, never remediates</span>
      <span>{generated}</span>
    </div>

  </main>
</body>
</html>
"""


def build_html(data: dict) -> str:
    return HTML_TEMPLATE.format(
        target        = data["target"],
        generated     = data["generated"],
        source_file   = data["source_file"],
        total         = data["total"],
        critical      = data["critical"],
        high          = data["high"],
        fixable       = data["fixable"],
        assessment_html = md_to_html(data["assessment_md"]),
        findings_rows = findings_rows(data["findings"]),
    )


# ---------------------------------------------------------------------------
# 4. Write the HTML and serve it
# ---------------------------------------------------------------------------

def main() -> None:
    md_path = sys.argv[1] if len(sys.argv) > 1 else latest_report()
    if not os.path.exists(md_path):
        sys.exit(f"File not found: {md_path}")

    print(f"Reading:  {md_path}")
    data = parse_report(md_path)
    html = build_html(data)

    here = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(here, "reports")
    out_path = os.path.join(reports_dir, "index.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Written:  {out_path}")

    port = 8080
    url  = f"http://localhost:{port}/index.html"
    print(f"\nServing at {url}  (Ctrl+C to stop)\n")

    # Open browser after a short delay so the server is up first
    Timer(0.8, lambda: webbrowser.open(url)).start()

    os.chdir(reports_dir)
    handler = http.server.SimpleHTTPRequestHandler
    handler.log_message = lambda *a: None  # silence per-request noise
    with http.server.HTTPServer(("", port), handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
