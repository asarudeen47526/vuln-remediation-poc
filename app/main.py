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

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

# Project-root packages (remediation_core, config, llm_client) are importable
# because uvicorn is run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import ALLOWED_ACTIONS, DRY_RUN, HEALTH_URL, PLAYBOOK, SSH_KEY, SSH_USER, TARGET_HOST

from . import crud, models, schemas
from .database import Base, SessionLocal, engine, get_db

# Create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="VulnGuard AI", version="2.0.0")

_STATIC = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_STATIC), name="static")

_executor = ThreadPoolExecutor(max_workers=4)


# ─── helpers ────────────────────────────────────────────────────────────────

def _finding_to_dict(f: models.Finding) -> dict:
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
        "plan_status": f.plan_status,
        "plan": plan,
        "pending_rollback_token": pending_token,
        "approved_rollback_token": approved_token,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    }


def _gen_plan_bg(finding_id: int):
    """Generate + validate a plan for one finding; store result in DB."""
    from remediation_core import make_plan, validate_plan

    db = SessionLocal()
    try:
        f = crud.get_finding(db, finding_id)
        if not f:
            return
        finding_dict = {
            "cve": f.cve_id,
            "package": f.package,
            "installed": f.installed_version,
            "fixed": f.fixed_version,
            "severity": f.severity,
        }
        if DRY_RUN:
            plan = {
                "action": "update_package",
                "package": f.package,
                "reboot_required": False,
                "services_to_restart": [],
                "reason": f"[DRY-RUN] Update {f.package} from {f.installed_version} to {f.fixed_version} to fix {f.cve_id}.",
                "restore_plan": f"[DRY-RUN] dnf history undo last — restores {f.package} to {f.installed_version}.",
            }
        else:
            plan = make_plan(finding_dict)
        ok, why = validate_plan(plan, finding_dict)
        if ok:
            crud.upsert_plan(db, finding_id, plan, None)
            crud.update_finding(db, finding_id, plan_status="ready")
        else:
            crud.upsert_plan(db, finding_id, None, f"Validation failed: {why}")
            crud.update_finding(db, finding_id, plan_status="error")
    except Exception as exc:  # noqa: BLE001
        crud.upsert_plan(db, finding_id, None, str(exc))
        crud.update_finding(db, finding_id, plan_status="error")
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
    return [_finding_to_dict(f) for f in findings]


@app.post("/api/v1/applications/{ait_id}/import")
async def import_scan(
    ait_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")

    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}") from exc

    raw: list[dict] = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            raw.append({
                "cve": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion"),
                "severity": v.get("Severity"),
                "title": v.get("Title", ""),
                "os": result.get("Target", ""),
            })

    scan = crud.create_scan(db, ait_id, file.filename or "upload.json", len(raw))
    total = 0
    for f in raw:
        category = "npt" if not f.get("fixed") else "vulnerability"
        obj = crud.create_finding(db, scan.id, ait_id, f, category)
        total += 1
        if category == "npt":
            # No fix exists — mark plan as not applicable immediately; no LLM call needed
            crud.upsert_plan(db, obj.id, None, "No fix available (NPT finding — no fixed version published).")
            crud.update_finding(db, obj.id, plan_status="na")
        else:
            # Submit to thread pool so the LLM subprocess doesn't block the event loop
            _executor.submit(_gen_plan_bg, obj.id)

    return {"scan_id": scan.id, "imported": total, "ait_id": ait_id}


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

def _run_analysis_bg(ait_id: str) -> None:
    """Run full LLM analysis for an AIT and store per-CVE results in DB."""
    import re
    db = SessionLocal()
    try:
        findings_db = crud.list_findings(db, ait_id)
        if not findings_db:
            return
        findings = [
            {"cve": f.cve_id, "package": f.package, "severity": f.severity,
             "installed": f.installed_version or "", "fixed": f.fixed_version or ""}
            for f in findings_db
        ]
        from analyze import llm_analysis, _extract_per_cve
        analysis = llm_analysis(findings)
        per_cve = _extract_per_cve(analysis)
        for f in findings_db:
            text = per_cve.get(f.cve_id, analysis)
            crud.update_finding(db, f.id, analysis_md=text)
    except Exception as exc:  # noqa: BLE001
        print(f"[analyze-bg] {ait_id}: {exc}")
    finally:
        db.close()


@app.post("/api/v1/applications/{ait_id}/analyze")
def run_analysis(ait_id: str, background_tasks: BackgroundTasks,
                 db: Session = Depends(get_db)):
    if not crud.get_application(db, ait_id):
        raise HTTPException(404, "Application not found")
    background_tasks.add_task(_run_analysis_bg, ait_id)
    return {"status": "started", "ait_id": ait_id}


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
