"""FastAPI application — VulnGuard AI v2.

Run from project root:
    uvicorn app.main:app --reload --port 8080
"""
import json
import os
import secrets
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

# Project-root packages (remediation_core, config, llm_client) are importable
# because uvicorn is run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import AI_ENABLED, ALLOWED_ACTIONS, DRY_RUN, HEALTH_URL, PLAYBOOK, SSH_KEY, SSH_USER, TARGET_HOST

from . import crud, models, schemas
from .database import Base, SessionLocal, engine, get_db

# Create tables on startup
Base.metadata.create_all(bind=engine)

# Idempotent column migrations for new fields added after initial schema creation
try:
    from sqlalchemy import text as _sql_text
    with engine.connect() as _conn:
        _conn.execute(_sql_text(
            "ALTER TABLE findings ADD COLUMN IF NOT EXISTS dep_note TEXT"
        ))
        _conn.execute(_sql_text(
            "ALTER TABLE applications ADD COLUMN IF NOT EXISTS dep_report JSON"
        ))
        _conn.commit()
except Exception as _me:
    print(f"[startup] column migration skipped: {_me}")

app = FastAPI(title="VulnGuard AI", version="2.0.0")

_STATIC = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_STATIC), name="static")

_executor = ThreadPoolExecutor(max_workers=4)


# ─── helpers ────────────────────────────────────────────────────────────────

def _finding_to_dict(f: models.Finding, family_group: str = "") -> dict:
    plan = None
    if f.remediation_plan:
        rp = f.remediation_plan
        plan = {
            "action": rp.action,
            "package": rp.package,
            "reboot_required": rp.reboot_required,
            "services_to_restart": rp.services_to_restart or "",
            "reason": rp.reason,
            "restore_plan": rp.restore_plan,
            "plan_json": rp.plan_json,
            "plan_error": rp.plan_error,
            "generated_at": rp.generated_at.isoformat() if rp.generated_at else None,
        }

    # Latest pending rollback approval token (if any)
    pending_token = None
    approved_token = None
    for apv in (f.approvals or []):
        if apv.approval_type == "rollback":
            if apv.status == "pending":
                pending_token = apv.token
            elif apv.status == "approved":
                approved_token = apv.token

    return {
        "id": f.id,
        "ait_id": f.ait_id,
        "cve_id": f.cve_id,
        "package": f.package,
        "severity": f.severity,
        "installed_version": f.installed_version,
        "fixed_version": f.fixed_version,
        "title": f.title or f.cve_id,
        "os_target": f.os_target,
        "category": f.category,
        "status": f.status,
        "analysis_md": f.analysis_md,
        "dep_info": json.loads(f.dep_note) if f.dep_note else None,
        "plan_status": f.plan_status,
        "plan": plan,
        "pending_rollback_token": pending_token,
        "approved_rollback_token": approved_token,
        "family_group": family_group,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    }


def _gen_plan_bg(finding_id: int):
    """Generate + validate a plan for one finding; store result in DB.

    Pattern: read → close DB → LLM call → open DB → write → close.
    This releases the connection before the slow LLM call so the pool
    is not exhausted when multiple findings are queued concurrently.
    """
    from remediation_core import make_plan, validate_plan

    # ── Step 1: read finding (fast) ──────────────────────────────────────────
    db = SessionLocal()
    try:
        f = crud.get_finding(db, finding_id)
        if not f:
            return
        finding_dict = {
            "cve": f.cve_id, "package": f.package,
            "installed": f.installed_version, "fixed": f.fixed_version,
            "severity": f.severity,
        }
        pkg = f.package
        installed, fixed, cve_id = f.installed_version, f.fixed_version, f.cve_id
    finally:
        db.close()  # release connection before LLM call

    # ── Step 2: plan generation (LLM only in live mode with AI enabled) ──────
    plan = None
    error = None
    try:
        if DRY_RUN:
            plan = {
                "action": "update_package",
                "package": pkg,
                "reboot_required": False,
                "services_to_restart": [],
                "reason": f"[DRY-RUN] Update {pkg} from {installed} to {fixed} to fix {cve_id}.",
                "restore_plan": f"[DRY-RUN] dnf history undo last — restores {pkg} to {installed}.",
            }
        else:
            plan = make_plan(finding_dict)
        if plan is not None:
            ok, why = validate_plan(plan, finding_dict)
            if not ok:
                plan, error = None, f"Validation failed: {why}"
    except Exception as exc:  # noqa: BLE001
        plan, error = None, str(exc)

    # ── Step 3: write result (fast) ──────────────────────────────────────────
    db = SessionLocal()
    try:
        if plan:
            crud.upsert_plan(db, finding_id, plan, None)
            crud.update_finding(db, finding_id, plan_status="ready")
        else:
            crud.upsert_plan(db, finding_id, None, error)
            crud.update_finding(db, finding_id, plan_status="error")
    except Exception as exc:  # noqa: BLE001
        print(f"[plan-bg] write failed for finding {finding_id}: {exc}")
    finally:
        db.close()


# ─── UI ──────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def serve_ui():
    return FileResponse(os.path.join(_STATIC, "index.html"))


# ─── Applications ────────────────────────────────────────────────────────────

@app.get("/api/v1/applications")
def list_apps(db: Session = Depends(get_db)):
    apps = crud.list_applications(db)
    return [
        {**{c.name: getattr(a, c.name) for c in a.__table__.columns},
         "stats": crud.get_app_stats(db, a.ait_id),
         "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in apps
    ]


@app.post("/api/v1/applications", status_code=201)
def create_app(data: schemas.ApplicationCreate, db: Session = Depends(get_db)):
    if crud.get_application(db, data.ait_id):
        raise HTTPException(400, "AIT ID already exists")
    obj = crud.create_application(db, data)
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}


@app.get("/api/v1/applications/{ait_id}")
def get_app(ait_id: str, db: Session = Depends(get_db)):
    obj = crud.get_application(db, ait_id)
    if not obj:
        raise HTTPException(404, "Application not found")
    return {
        **{c.name: getattr(obj, c.name) for c in obj.__table__.columns},
        "stats": crud.get_app_stats(db, ait_id),
        "created_at": obj.created_at.isoformat() if obj.created_at else None,
    }


@app.delete("/api/v1/applications/{ait_id}", status_code=204)
def delete_app(ait_id: str, db: Session = Depends(get_db)):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    crud.delete_application(db, ait_id)


@app.get("/api/v1/applications/{ait_id}/stats")
def get_stats(ait_id: str, db: Session = Depends(get_db)):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404)
    return crud.get_app_stats(db, ait_id)


@app.get("/api/v1/config")
def get_server_config():
    """Expose non-secret server config flags to the UI."""
    return {"ai_enabled": AI_ENABLED, "dry_run": DRY_RUN}


@app.get("/api/v1/applications/{ait_id}/findings")
def list_findings(
    ait_id: str,
    category: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    findings = crud.list_findings(db, ait_id, category=category, status=status)
    fgmap = crud.get_family_group_map(db, ait_id)
    return [_finding_to_dict(f, fgmap.get(f.package, "")) for f in findings]


def _parse_trivy_report(data: dict) -> list[dict]:
    """Parse all Trivy result classes into a unified flat list of finding dicts.

    Handles: Vulnerabilities (os-pkgs / lang-pkgs), Misconfigurations (IaC/config),
    Secrets, and Licenses. Private keys in _cat / _resolution drive category + plan.
    """
    raw: list[dict] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")

        for v in result.get("Vulnerabilities") or []:
            raw.append({
                "cve": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion"),
                "severity": v.get("Severity", "UNKNOWN"),
                "title": v.get("Title", ""),
                "os": target,
                "_status": (v.get("Status") or "").lower(),
            })

        for m in result.get("Misconfigurations") or []:
            raw.append({
                "cve": m.get("AVDID") or m.get("ID"),
                "package": m.get("Type", "IaC"),
                "installed": None,
                "fixed": None,
                "severity": m.get("Severity", "UNKNOWN"),
                "title": m.get("Title", ""),
                "os": target,
                "_cat": "other",
                "_resolution": m.get("Resolution") or "Fix the misconfiguration as described in the check details.",
            })

        for s in result.get("Secrets") or []:
            raw.append({
                "cve": s.get("RuleID"),
                "package": s.get("Category", "secret"),
                "installed": None,
                "fixed": None,
                "severity": s.get("Severity", "UNKNOWN"),
                "title": s.get("Title", ""),
                "os": target,
                "_cat": "secret",
                "_resolution": "Rotate or remove the exposed credential immediately and audit all access logs.",
            })

        for lic in result.get("Licenses") or []:
            raw.append({
                "cve": lic.get("Name"),
                "package": lic.get("PkgName", "unknown"),
                "installed": lic.get("FilePath", ""),
                "fixed": None,
                "severity": lic.get("Severity", "UNKNOWN"),
                "title": f"{lic.get('Name', '')} license — {lic.get('PkgName', '')}",
                "os": target,
                "_cat": "other",
                "_resolution": "Review license compatibility with your legal team. Replace with a permissively-licensed alternative or obtain a commercial license.",
            })

    return raw


def _detect_ecosystem(pkg: str, os_target: str) -> str:
    """Return the package manager ecosystem for a finding.

    Returns one of: 'os', 'maven', 'npm', 'pip', 'gem', 'other'.
    Used to decide whether dnf/Ansible can patch this or whether a
    build-system advisory is needed instead.
    """
    if ":" in pkg:                              # Maven groupId:artifactId
        return "maven"
    ot = (os_target or "").lower()
    if "node-pkg" in ot or "node_modules" in ot:
        return "npm"
    if "python-pkg" in ot or "pip" in ot:
        return "pip"
    if "gem" in ot or "ruby-gems" in ot:
        return "gem"
    if "jar" in ot:                             # Java target not already Maven-formatted
        return "maven"
    return "os"


def _app_lib_advisory(pkg: str, fixed: str, ecosystem: str) -> str:
    """Realistic remediation text for application-bundled libraries.

    These libraries are shipped inside WAR/JAR/node_modules/virtualenvs and
    cannot be patched by dnf.  The text is stored as plan_error so the UI
    surfaces it in the Remediation Plan column.
    """
    target_ver = f" to {fixed}" if fixed else ""
    if ecosystem == "maven":
        artifact = pkg.split(":")[-1] if ":" in pkg else pkg
        return (
            f"{pkg} is a Java library bundled inside your application — dnf cannot patch it. "
            f"Steps: (1) run find /opt/app -name '{artifact}-*.jar' to confirm the version present; "
            f"(2) update the version{target_ver} in pom.xml or build.gradle; "
            f"(3) rebuild with 'mvn clean package -DskipTests' or 'gradle build'; "
            f"(4) redeploy the new artifact and restart the application service; "
            f"(5) verify with 'trivy fs --scanners vuln /opt/app'."
        )
    if ecosystem == "npm":
        cmd = f"npm install {pkg}@{fixed}" if fixed else f"npm update {pkg}"
        return (
            f"{pkg} is a Node.js library installed via npm — dnf cannot patch it. "
            f"Steps: (1) in your application directory run '{cmd}'; "
            f"(2) run your test suite; "
            f"(3) redeploy and restart the Node.js service; "
            f"(4) verify with 'trivy fs --scanners vuln /opt/app'."
        )
    if ecosystem == "pip":
        cmd = f"pip install '{pkg}=={fixed}'" if fixed else f"pip install --upgrade {pkg}"
        return (
            f"{pkg} is a Python package — dnf cannot patch it. "
            f"Steps: (1) activate your virtualenv and run '{cmd}'; "
            f"(2) run your test suite; "
            f"(3) restart the application service to load the updated library; "
            f"(4) verify with 'trivy fs --scanners vuln /opt/app'."
        )
    if ecosystem == "gem":
        return (
            f"{pkg} is a Ruby gem — dnf cannot patch it. "
            f"Steps: (1) update '{pkg}'{target_ver} in your Gemfile; "
            f"(2) run 'bundle update {pkg}'; "
            f"(3) redeploy and restart the Ruby service."
        )
    return (
        f"{pkg} is an application-bundled library{target_ver}. "
        "Update the dependency in your build system, rebuild, and redeploy. "
        "dnf/Ansible cannot patch this."
    )


def _import_to_db(db, ait_id: str, scan_id: int, raw: list[dict]) -> int:
    """Upsert findings from a parsed report; skip any that are already in DB.

    Returns count of records touched (created or updated).
    """
    total = 0
    for f in raw:
        _cat = f.get("_cat")
        _status = f.get("_status", "")
        if _cat == "secret":
            category = "secret"
        elif _cat == "other":
            category = "other"
        elif _cat:
            category = _cat
        elif _status == "end_of_life":
            category = "eol"
        elif not f.get("fixed"):
            category = "npt"
        else:
            category = "vulnerability"

        obj = crud.create_finding(db, scan_id, ait_id, f, category)
        total += 1

        if category == "eol":
            if obj.plan_status != "na":
                crud.upsert_plan(db, obj.id, None,
                    "This package/runtime has reached End of Life and no longer receives security patches. "
                    "Upgrade to a currently supported version.")
                crud.update_finding(db, obj.id, plan_status="na")
        elif category in ("npt", "secret", "other"):
            if obj.plan_status != "na":
                resolution = f.get("_resolution", "No fix available.")
                crud.upsert_plan(db, obj.id, None, resolution)
                crud.update_finding(db, obj.id, plan_status="na")
        else:  # vulnerability
            ecosystem = _detect_ecosystem(f.get("package", ""), f.get("os", ""))
            if ecosystem == "os":
                # OS package — Ansible/dnf pipeline applies
                if obj.plan_status not in ("ready",) and AI_ENABLED:
                    _executor.submit(_gen_plan_bg, obj.id)
            else:
                # Application-bundled library — realistic build-system advisory
                if obj.plan_status != "na":
                    advisory = _app_lib_advisory(
                        f.get("package", ""), f.get("fixed", ""), ecosystem
                    )
                    crud.upsert_plan(db, obj.id, None, advisory)
                    crud.update_finding(db, obj.id, plan_status="na")

    return total


def _parse_upload(content: bytes, filename: str) -> list[dict] | None:
    """Parse uploaded file content as Trivy JSON or CSV.

    Returns flat findings list compatible with _import_to_db, or None on failure.
    """
    name_lower = filename.lower()
    if name_lower.endswith(".csv"):
        from remediation_core import parse_csv
        return parse_csv(content)
    # Try JSON (Trivy report or fallback)
    try:
        data = json.loads(content)
        return _parse_trivy_report(data)
    except (json.JSONDecodeError, KeyError, TypeError):
        # Last-chance: maybe it's a headerless CSV with .json extension
        try:
            from remediation_core import parse_csv
            result = parse_csv(content)
            if result:
                return result
        except Exception:
            pass
    return None


@app.post("/api/v1/applications/{ait_id}/import")
async def import_scan(
    ait_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")

    content = await file.read()
    raw = _parse_upload(content, file.filename or "upload")
    if raw is None:
        raise HTTPException(400, "File must be a Trivy JSON report or a vulnerability CSV")

    scan = crud.create_scan(db, ait_id, file.filename or "upload.json", len(raw))
    total = _import_to_db(db, ait_id, scan.id, raw)

    if total > 0 and AI_ENABLED:
        pkgs = sorted({f["package"] for f in raw if f.get("package")})
        _executor.submit(_run_analysis_bg, ait_id)
        if pkgs:
            _executor.submit(_compute_groups_bg, ait_id, pkgs)

    return {"scan_id": scan.id, "imported": total, "ait_id": ait_id}


@app.post("/api/v1/import-scan", status_code=201)
async def import_scan_create(
    ait_id: str = Form(...),
    name: str = Form(""),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Import a Trivy JSON or CSV report, auto-creating the AIT if it does not exist."""
    if not crud.get_application(db, ait_id):
        crud.create_application(db, schemas.ApplicationCreate(
            ait_id=ait_id, name=name.strip() or ait_id,
        ))

    content = await file.read()
    raw = _parse_upload(content, file.filename or "upload")
    if raw is None:
        raise HTTPException(400, "File must be a Trivy JSON report or a vulnerability CSV")

    scan = crud.create_scan(db, ait_id, file.filename or "upload.json", len(raw))
    total = _import_to_db(db, ait_id, scan.id, raw)

    if total > 0 and AI_ENABLED:
        pkgs = sorted({f["package"] for f in raw if f.get("package")})
        _executor.submit(_run_analysis_bg, ait_id)
        if pkgs:
            _executor.submit(_compute_groups_bg, ait_id, pkgs)

    return {"scan_id": scan.id, "imported": total, "ait_id": ait_id, "created": True}


# ─── Findings ────────────────────────────────────────────────────────────────

@app.get("/api/v1/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = crud.get_finding(db, finding_id)
    if not f:
        raise HTTPException(404)
    return _finding_to_dict(f)


@app.post("/api/v1/findings/{finding_id}/generate-plan")
def generate_plan(finding_id: int, db: Session = Depends(get_db)):
    f = crud.get_finding(db, finding_id)
    if not f:
        raise HTTPException(404)
    if f.plan_status == "ready":
        return _finding_to_dict(f)
    crud.update_finding(db, finding_id, plan_status="pending")
    _executor.submit(_gen_plan_bg, finding_id)
    return {"status": "generating", "finding_id": finding_id}


@app.post("/api/v1/applications/{ait_id}/generate-plans")
def generate_plans(ait_id: str, db: Session = Depends(get_db)):
    """Trigger plan generation for all pending/error vulnerability findings in an AIT."""
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    findings = crud.list_findings(db, ait_id, category="vulnerability")
    submitted = 0
    for f in findings:
        if f.plan_status in ("pending", "error"):
            crud.update_finding(db, f.id, plan_status="pending")
            _executor.submit(_gen_plan_bg, f.id)
            submitted += 1
    return {"submitted": submitted, "ait_id": ait_id}


def _compute_groups_bg(ait_id: str, packages: list) -> None:
    """Call LLM to group packages into logical families; store results in DB.

    Skips when all packages are already grouped.
    """
    # Skip if every package already has a group — avoids a redundant LLM call
    db = SessionLocal()
    try:
        existing_map = crud.get_family_group_map(db, ait_id)
    finally:
        db.close()
    if all(p in existing_map for p in packages):
        return

    import re
    from llm_client import generate

    SYSTEM = (
        "You are a software security expert. Your job is to group security findings "
        "into logical families based on shared technology, component, or update action. "
        "A family is a set of packages/items that belong to the same technology "
        "ecosystem, share a common source, or are updated together in one operation. "
        "Consider: shared source packages, library + runtime/dev variants, "
        "application + modules/plugins, language interpreters + standard libraries. "
        "This applies to all finding types: OS packages (RPM/deb), Python/Node/Java libs, "
        "and NPT items (no-fix vulnerabilities) — group by their core technology. "
        "Respond ONLY with valid JSON. No prose, no markdown fences."
    )
    USER = (
        "Group these security findings into logical update families.\n\n"
        "Rules:\n"
        "- Group by shared technology/component "
        "(e.g. nginx + nginx-mod-* → 'nginx'; openssl + openssl-libs → 'openssl')\n"
        "- Library with runtime/dev variants belong together\n"
        "- Application modules/plugins belong with their parent "
        "(e.g. httpd + mod_ssl → 'httpd')\n"
        "- Language interpreter + stdlib belong together "
        "(e.g. python3 + python3-libs → 'python3')\n"
        "- NPT items (no-fix) should also be grouped by their core technology\n"
        "- A package with no relatives is its own single-item family\n"
        "- Every item must appear in exactly one group\n"
        "- Family name = the base/root package or technology name (lowercase)\n\n"
        f"Items to group:\n{json.dumps(packages)}\n\n"
        "Return only JSON (no markdown):\n"
        '{\n'
        '  "groups": [\n'
        '    {\n'
        '      "family": "nginx",\n'
        '      "reason": "nginx and all nginx-mod-* share source RPM and version, updated atomically",\n'
        '      "packages": ["nginx", "nginx-mod-http-image-filter", "nginx-mod-stream"]\n'
        '    }\n'
        '  ]\n'
        '}'
    )

    # ── Step 1: LLM call (slow, no DB connection held) ───────────────────────
    groups = []
    try:
        raw = generate(SYSTEM, USER).strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw.rstrip())
        data = json.loads(raw)
        groups = data.get("groups", [])
        assigned = {pkg for g in groups for pkg in g.get("packages", [])}
        for pkg in packages:
            if pkg not in assigned:
                groups.append({"family": pkg, "reason": "not grouped by LLM", "packages": [pkg]})
    except Exception as exc:
        groups = [{"family": p, "reason": f"LLM unavailable: {exc}", "packages": [p]}
                  for p in packages]

    # ── Step 2: write results (fast) ─────────────────────────────────────────
    db = SessionLocal()
    try:
        crud.upsert_family_groups(db, ait_id, groups)
    except Exception as exc:
        print(f"[groups-bg] write failed for {ait_id}: {exc}")
    finally:
        db.close()


@app.post("/api/v1/applications/{ait_id}/compute-groups")
def compute_groups(ait_id: str, db: Session = Depends(get_db)):
    """Ask the LLM to intelligently group packages into logical update families."""
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    findings = crud.list_findings(db, ait_id)
    packages = sorted({f.package for f in findings if f.package})
    if not packages:
        return {"status": "ok", "message": "No packages to group", "packages": 0}
    _executor.submit(_compute_groups_bg, ait_id, packages)
    return {"status": "computing", "packages": len(packages),
            "message": f"LLM grouping {len(packages)} package(s) in background"}


@app.post("/api/v1/findings/{finding_id}/remediate")
def remediate(finding_id: int, db: Session = Depends(get_db)):
    f = crud.get_finding(db, finding_id)
    if not f:
        raise HTTPException(404)
    if f.status not in ("open", "deferred", "skipped"):
        raise HTTPException(400, f"Cannot remediate: current status is '{f.status}'")
    if not f.remediation_plan or f.plan_status != "ready":
        raise HTTPException(400, "No validated plan available — wait for plan generation")

    plan = f.remediation_plan.plan_json
    finding_dict = {
        "cve": f.cve_id, "package": f.package,
        "installed": f.installed_version, "fixed": f.fixed_version,
        "severity": f.severity,
    }

    if DRY_RUN:
        rc = 0
        output = "[DRY_RUN] ansible-playbook skipped"
    else:
        services_str = ",".join(plan.get("services_to_restart") or [])
        cmd = [
            "ansible-playbook", "-i", f"{TARGET_HOST},", PLAYBOOK,
            "-u", SSH_USER, "--private-key", SSH_KEY,
            "-e", f"pkg={plan['package']}",
            "-e", f"health_url={HEALTH_URL}",
            "-e", f"services_to_restart={services_str}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        rc = result.returncode
        output = result.stdout + result.stderr

    success = rc == 0
    new_status = "remediated" if success else "open"
    crud.update_finding(db, finding_id, status=new_status)
    crud.create_action(db, finding_id, f.ait_id, "remediate", success=success, output=output)

    from remediation_core import audit
    audit("web-ui", finding_dict, plan, "success" if success else "failed_rolled_back")

    return {"success": success, "status": new_status, "rc": rc, "output": output[:500]}


@app.post("/api/v1/applications/{ait_id}/remediate-bulk")
def remediate_bulk(ait_id: str, data: schemas.BulkRemediateRequest, db: Session = Depends(get_db)):
    """Run ONE Ansible play that fixes a whole package group (multiple CVEs)."""
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    findings = [crud.get_finding(db, fid) for fid in data.finding_ids]
    findings = [f for f in findings if f and f.ait_id == ait_id]
    if not findings:
        raise HTTPException(400, "No valid findings for this AIT")
    for f in findings:
        if f.status not in ("open", "deferred", "skipped"):
            raise HTTPException(400, f"Finding {f.id} has status '{f.status}' — cannot remediate")
    rep = next((f for f in findings if f.plan_status == "ready" and f.remediation_plan), None)
    if not rep:
        raise HTTPException(400, "No validated plan available in this group")
    plan = rep.remediation_plan.plan_json
    if DRY_RUN:
        rc = 0
        output = f"[DRY_RUN] ansible-playbook skipped — would update {plan['package']}"
    else:
        services_str = ",".join(plan.get("services_to_restart") or [])
        cmd = [
            "ansible-playbook", "-i", f"{TARGET_HOST},", PLAYBOOK,
            "-u", SSH_USER, "--private-key", SSH_KEY,
            "-e", f"pkg={plan['package']}",
            "-e", f"health_url={HEALTH_URL}",
            "-e", f"services_to_restart={services_str}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        rc = result.returncode
        output = result.stdout + result.stderr
    success = rc == 0
    new_status = "remediated" if success else "open"
    for f in findings:
        crud.update_finding(db, f.id, status=new_status)
        crud.create_action(db, f.id, f.ait_id, "remediate", success=success, output=output)
    from remediation_core import audit
    audit("web-ui-bulk", {
        "cve": ",".join(f.cve_id for f in findings),
        "package": plan["package"],
        "installed": rep.installed_version,
        "fixed": rep.fixed_version,
        "severity": rep.severity,
    }, plan, "success" if success else "failed_rolled_back")
    return {"success": success, "status": new_status, "rc": rc,
            "remediated_count": len(findings), "output": output[:500]}


@app.post("/api/v1/findings/{finding_id}/defer")
def defer(finding_id: int, db: Session = Depends(get_db)):
    f = crud.get_finding(db, finding_id)
    if not f:
        raise HTTPException(404)
    crud.update_finding(db, finding_id, status="deferred")
    crud.create_action(db, finding_id, f.ait_id, "defer", success=True)
    return {"status": "deferred"}


@app.post("/api/v1/findings/{finding_id}/skip")
def skip(finding_id: int, db: Session = Depends(get_db)):
    f = crud.get_finding(db, finding_id)
    if not f:
        raise HTTPException(404)
    crud.update_finding(db, finding_id, status="skipped")
    crud.create_action(db, finding_id, f.ait_id, "skip", success=True)
    return {"status": "skipped"}


@app.post("/api/v1/findings/{finding_id}/request-rollback")
def request_rollback(
    finding_id: int,
    data: schemas.ApprovalCreate,
    db: Session = Depends(get_db),
):
    f = crud.get_finding(db, finding_id)
    if not f:
        raise HTTPException(404)
    if f.status != "remediated":
        raise HTTPException(400, "Rollback only available for remediated findings")
    # Only one pending rollback at a time
    for apv in f.approvals:
        if apv.approval_type == "rollback" and apv.status == "pending":
            return {"token": apv.token, "status": "pending", "existing": True}

    token = secrets.token_urlsafe(32)
    apv = crud.create_approval(db, finding_id, f.ait_id, "rollback", token, data.approver_email)
    return {"token": token, "approval_id": apv.id, "status": "pending"}


@app.post("/api/v1/findings/{finding_id}/rollback")
def execute_rollback(finding_id: int, token: str, db: Session = Depends(get_db)):
    f = crud.get_finding(db, finding_id)
    if not f:
        raise HTTPException(404)
    if f.status != "remediated":
        raise HTTPException(400, "Nothing to roll back")

    apv = crud.get_approval_by_token(db, token)
    if not apv or apv.finding_id != finding_id:
        raise HTTPException(403, "Invalid rollback token")
    if apv.status != "approved":
        raise HTTPException(403, f"Rollback not yet approved (status: {apv.status})")

    if DRY_RUN:
        rc, output = 0, "[DRY_RUN] dnf history undo last skipped"
    else:
        cmd = [
            "ansible", f"{TARGET_HOST},",
            "-u", SSH_USER, "--private-key", SSH_KEY,
            "-m", "command",
            "-a", f"dnf history undo last -y",
            "--become",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        rc, output = result.returncode, result.stdout + result.stderr

    success = rc == 0
    crud.update_finding(db, finding_id, status="rolled_back" if success else "remediated")
    crud.create_action(db, finding_id, f.ait_id, "rollback", success=success, output=output)
    return {"success": success, "rc": rc}


# ─── Approvals ────────────────────────────────────────────────────────────────

@app.get("/api/v1/approvals")
def list_approvals(
    ait_id: Optional[str] = None,
    status: Optional[str] = "pending",
    db: Session = Depends(get_db),
):
    apvs = crud.list_approvals(db, ait_id=ait_id, status=status)
    result = []
    for a in apvs:
        result.append({
            "id": a.id,
            "finding_id": a.finding_id,
            "ait_id": a.ait_id,
            "approval_type": a.approval_type,
            "token": a.token,
            "status": a.status,
            "approver_email": a.approver_email,
            "notes": a.notes,
            "requested_at": a.requested_at.isoformat() if a.requested_at else None,
            "responded_at": a.responded_at.isoformat() if a.responded_at else None,
        })
    return result


@app.get("/api/v1/approvals/{token}")
def get_approval(token: str, db: Session = Depends(get_db)):
    apv = crud.get_approval_by_token(db, token)
    if not apv:
        raise HTTPException(404)
    return {
        "id": apv.id,
        "finding_id": apv.finding_id,
        "ait_id": apv.ait_id,
        "approval_type": apv.approval_type,
        "token": token,
        "status": apv.status,
        "approver_email": apv.approver_email,
        "notes": apv.notes,
        "requested_at": apv.requested_at.isoformat() if apv.requested_at else None,
    }


@app.post("/api/v1/approvals/{token}/approve")
def approve_rollback(token: str, data: schemas.ApprovalAction, db: Session = Depends(get_db)):
    apv = crud.get_approval_by_token(db, token)
    if not apv:
        raise HTTPException(404)
    if apv.status != "pending":
        raise HTTPException(400, f"Already {apv.status}")
    crud.update_approval(db, apv.id, "approved", data.notes, data.approver_email)
    return {"status": "approved"}


@app.post("/api/v1/approvals/{token}/reject")
def reject_rollback(token: str, data: schemas.ApprovalAction, db: Session = Depends(get_db)):
    apv = crud.get_approval_by_token(db, token)
    if not apv:
        raise HTTPException(404)
    if apv.status != "pending":
        raise HTTPException(400, f"Already {apv.status}")
    crud.update_approval(db, apv.id, "rejected", data.notes, data.approver_email)
    return {"status": "rejected"}


# ─── Analysis ────────────────────────────────────────────────────────────────

def _run_analysis_bg(ait_id: str, force_ids: list[int] = None) -> None:
    """Run LLM analysis for findings that do not yet have analysis_md.

    If force_ids is provided, re-analyze only those finding IDs (clearing any
    existing analysis_md first). Otherwise skip findings that already have analysis.
    Pattern: read → close DB → LLM call → open DB → write → close.
    Skips when all targeted findings already have analysis.
    """
    # ── Step 1: read findings, determine which to analyze (fast) ─────────────
    db = SessionLocal()
    try:
        findings_db = crud.list_findings(db, ait_id)
        if force_ids:
            force_set = set(force_ids)
            # Clear existing analysis for forced IDs so LLM re-runs them
            for f in findings_db:
                if f.id in force_set and f.analysis_md:
                    crud.update_finding(db, f.id, analysis_md=None)
            unanalyzed = [f for f in findings_db if f.id in force_set]
        else:
            unanalyzed = [f for f in findings_db if not f.analysis_md]
        if not unanalyzed:
            return  # nothing to do — avoids an LLM call entirely
        findings = [
            {"cve": f.cve_id, "package": f.package, "severity": f.severity,
             "installed": f.installed_version or "", "fixed": f.fixed_version or ""}
            for f in unanalyzed
        ]
        id_map = {f.cve_id: f.id for f in unanalyzed}
    finally:
        db.close()  # release connection before LLM call

    # ── Step 2: LLM analysis (slow, no DB connection held) ───────────────────
    try:
        from analyze import llm_analysis, _extract_per_cve
        analysis = llm_analysis(findings)
        per_cve = _extract_per_cve(analysis)
    except Exception as exc:  # noqa: BLE001
        print(f"[analyze-bg] {ait_id}: {exc}")
        return

    # ── Step 3: store results (fast) ─────────────────────────────────────────
    db = SessionLocal()
    try:
        for cve_id, finding_id in id_map.items():
            text = per_cve.get(cve_id, analysis)
            crud.update_finding(db, finding_id, analysis_md=text)
    except Exception as exc:  # noqa: BLE001
        print(f"[analyze-bg] store {ait_id}: {exc}")
    finally:
        db.close()


@app.post("/api/v1/applications/{ait_id}/analyze")
def run_analysis(ait_id: str, background_tasks: BackgroundTasks,
                 data: schemas.AnalyzeRequest = None,
                 db: Session = Depends(get_db)):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    force_ids = data.finding_ids if data else None
    background_tasks.add_task(_run_analysis_bg, ait_id, force_ids)
    return {"status": "started", "ait_id": ait_id, "force_ids": len(force_ids) if force_ids else None}


# ─── Dependency Intelligence ──────────────────────────────────────────────────

def _run_dep_check_bg(ait_id: str, live: bool = False) -> None:
    """Run dependency intelligence check for all findings in an AIT (background)."""
    try:
        import dep_agent
    except ImportError as exc:
        print(f"[dep-check-bg] dep_agent not importable: {exc}")
        return

    db = SessionLocal()
    try:
        app_obj = crud.get_application(db, ait_id)
        host = app_obj.host if app_obj else None
        findings_db = crud.list_findings(db, ait_id)
        findings = [
            {"cve": f.cve_id, "package": f.package, "severity": f.severity,
             "installed": f.installed_version or "", "fixed": f.fixed_version or ""}
            for f in findings_db
        ]
    finally:
        db.close()

    if not findings:
        return

    result = dep_agent.run_dep_check(findings, host=host if live else None, live=live)

    db = SessionLocal()
    try:
        crud.store_dep_report(db, ait_id, result)
        for f in result["findings_classified"]:
            dep_info = json.dumps({
                "risk":     f.get("dep_risk", "UNKNOWN"),
                "label":    f.get("dep_label", ""),
                "products": f.get("dep_products", []),
                "note":     f.get("dep_note", ""),
            })
            rows = (
                db.query(models.Finding)
                .filter(
                    models.Finding.ait_id == ait_id,
                    models.Finding.cve_id == f.get("cve", ""),
                    models.Finding.package == f.get("package", ""),
                )
                .all()
            )
            for row in rows:
                crud.update_finding(db, row.id, dep_note=dep_info)
    except Exception as exc:
        print(f"[dep-check-bg] store {ait_id}: {exc}")
    finally:
        db.close()


@app.post("/api/v1/applications/{ait_id}/dep-check")
def run_dep_check(
    ait_id: str,
    background_tasks: BackgroundTasks,
    data: schemas.DepCheckRequest = None,
    db: Session = Depends(get_db),
):
    """Trigger dependency intelligence check — discovers running products via SSH and
    classifies each finding as SAFE / CHECK_VERSION / VENDOR_BUNDLED / AT_RISK."""
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    live = data.live if data else False
    background_tasks.add_task(_run_dep_check_bg, ait_id, live)
    return {"status": "started", "ait_id": ait_id, "live": live}


@app.get("/api/v1/applications/{ait_id}/dep-report")
def get_dep_report_endpoint(ait_id: str, db: Session = Depends(get_db)):
    """Return the last dep-check result for the AIT (products found + per-finding risk)."""
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    report = crud.get_dep_report(db, ait_id)
    return {"ait_id": ait_id, "report": report}


@app.post("/api/v1/applications/{ait_id}/import-analysis")
async def import_analysis(ait_id: str, file: UploadFile = File(...),
                          db: Session = Depends(get_db)):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    import re
    content = (await file.read()).decode("utf-8", errors="replace")
    per_cve: dict = {}
    for part in re.split(r'\n(?=###\s+CVE-[\w-]+)', content):
        m = re.match(r'###\s+(CVE-[\w-]+)', part.strip())
        if m:
            per_cve[m.group(1)] = part.strip()
    if not per_cve:
        raise HTTPException(400, "No '### CVE-XXXX' sections found in report")
    findings = crud.list_findings(db, ait_id)
    updated = 0
    for f in findings:
        if f.cve_id in per_cve:
            crud.update_finding(db, f.id, analysis_md=per_cve[f.cve_id])
            updated += 1
    return {"imported": updated, "cves_in_report": list(per_cve.keys())}
