from datetime import datetime
from typing import Optional, List
from sqlalchemy.orm import Session, joinedload
from . import models, schemas


# ── Applications ────────────────────────────────────────────────────────────

def list_applications(db: Session) -> List[models.Application]:
    return db.query(models.Application).order_by(models.Application.ait_id).all()


def get_application(db: Session, ait_id: str) -> Optional[models.Application]:
    return db.query(models.Application).filter(models.Application.ait_id == ait_id).first()


def create_application(db: Session, data: schemas.ApplicationCreate) -> models.Application:
    obj = models.Application(**data.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def delete_application(db: Session, ait_id: str):
    db.query(models.Application).filter(models.Application.ait_id == ait_id).delete()
    db.commit()


def get_app_stats(db: Session, ait_id: str) -> dict:
    findings = db.query(models.Finding).filter(models.Finding.ait_id == ait_id).all()
    pending = db.query(models.Approval).filter(
        models.Approval.ait_id == ait_id,
        models.Approval.status == "pending",
    ).count()
    return {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
        "high": sum(1 for f in findings if f.severity == "HIGH"),
        "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
        "low": sum(1 for f in findings if f.severity == "LOW"),
        "open": sum(1 for f in findings if f.status == "open"),
        "remediated": sum(1 for f in findings if f.status == "remediated"),
        "deferred": sum(1 for f in findings if f.status == "deferred"),
        "skipped": sum(1 for f in findings if f.status == "skipped"),
        "rolled_back": sum(1 for f in findings if f.status == "rolled_back"),
        "vulnerabilities": sum(1 for f in findings if f.category == "vulnerability"),
        "npts": sum(1 for f in findings if f.category == "npt"),
        "pending_approvals": pending,
    }


# ── Scans ────────────────────────────────────────────────────────────────────

def create_scan(db: Session, ait_id: str, filename: str, count: int) -> models.Scan:
    obj = models.Scan(ait_id=ait_id, scan_file=filename, total_findings=count)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


# ── Findings ─────────────────────────────────────────────────────────────────

def create_finding(db: Session, scan_id: int, ait_id: str, f: dict, category: str) -> models.Finding:
    obj = models.Finding(
        scan_id=scan_id,
        ait_id=ait_id,
        cve_id=f["cve"],
        package=f["package"],
        severity=f.get("severity", "UNKNOWN"),
        installed_version=f.get("installed"),
        fixed_version=f.get("fixed"),
        title=f.get("title"),
        os_target=f.get("os"),
        category=category,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def list_findings(
    db: Session, ait_id: str,
    category: Optional[str] = None,
    status: Optional[str] = None,
) -> List[models.Finding]:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    q = (
        db.query(models.Finding)
        .options(
            joinedload(models.Finding.remediation_plan),
            joinedload(models.Finding.approvals),
        )
        .filter(models.Finding.ait_id == ait_id)
    )
    if category:
        q = q.filter(models.Finding.category == category)
    if status:
        q = q.filter(models.Finding.status == status)
    findings = q.all()
    findings.sort(key=lambda f: sev_order.get(f.severity, 9))
    return findings


def get_finding(db: Session, finding_id: int) -> Optional[models.Finding]:
    return db.query(models.Finding).filter(models.Finding.id == finding_id).first()


def update_finding(db: Session, finding_id: int, **kwargs):
    kwargs["updated_at"] = datetime.utcnow()
    db.query(models.Finding).filter(models.Finding.id == finding_id).update(kwargs)
    db.commit()


# ── Plans ────────────────────────────────────────────────────────────────────

def upsert_plan(db: Session, finding_id: int, plan_json: Optional[dict], error: Optional[str]):
    existing = db.query(models.RemediationPlan).filter(
        models.RemediationPlan.finding_id == finding_id
    ).first()

    fields: dict = {
        "plan_json": plan_json,
        "plan_error": error,
        "generated_at": datetime.utcnow(),
    }
    if plan_json:
        services = plan_json.get("services_to_restart") or []
        fields.update(
            action=plan_json.get("action"),
            package=plan_json.get("package"),
            reboot_required=bool(plan_json.get("reboot_required")),
            services_to_restart=",".join(services),
            reason=plan_json.get("reason"),
            restore_plan=plan_json.get("restore_plan"),
        )

    if existing:
        for k, v in fields.items():
            setattr(existing, k, v)
    else:
        obj = models.RemediationPlan(finding_id=finding_id, **fields)
        db.add(obj)
    db.commit()


# ── Actions ──────────────────────────────────────────────────────────────────

def create_action(
    db: Session, finding_id: int, ait_id: str,
    action_type: str, success: Optional[bool] = None, output: Optional[str] = None,
) -> models.RemediationAction:
    obj = models.RemediationAction(
        finding_id=finding_id,
        ait_id=ait_id,
        action_type=action_type,
        success=success,
        ansible_output=output,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


# ── Approvals ────────────────────────────────────────────────────────────────

def create_approval(
    db: Session, finding_id: int, ait_id: str,
    approval_type: str, token: str, approver_email: Optional[str] = None,
) -> models.Approval:
    obj = models.Approval(
        finding_id=finding_id,
        ait_id=ait_id,
        approval_type=approval_type,
        token=token,
        approver_email=approver_email,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def get_approval_by_token(db: Session, token: str) -> Optional[models.Approval]:
    return db.query(models.Approval).filter(models.Approval.token == token).first()


def update_approval(
    db: Session, approval_id: int, status: str,
    notes: Optional[str] = None, approver_email: Optional[str] = None,
):
    upd: dict = {"status": status, "responded_at": datetime.utcnow()}
    if notes:
        upd["notes"] = notes
    if approver_email:
        upd["approver_email"] = approver_email
    db.query(models.Approval).filter(models.Approval.id == approval_id).update(upd)
    db.commit()


def list_approvals(
    db: Session, ait_id: Optional[str] = None, status: Optional[str] = None,
) -> List[models.Approval]:
    q = db.query(models.Approval)
    if ait_id:
        q = q.filter(models.Approval.ait_id == ait_id)
    if status:
        q = q.filter(models.Approval.status == status)
    return q.order_by(models.Approval.requested_at.desc()).all()


# ── Package family groups (LLM-computed) ────────────────────────────────────

def upsert_family_groups(db: Session, ait_id: str, groups: list) -> None:
    """Store LLM-assigned package-family mappings. Upserts by (ait_id, package)."""
    for g in groups:
        family = g.get("family", "")
        reason = g.get("reason", "")
        for pkg in g.get("packages", []):
            existing = (
                db.query(models.PackageFamilyGroup)
                .filter(
                    models.PackageFamilyGroup.ait_id == ait_id,
                    models.PackageFamilyGroup.package == pkg,
                )
                .first()
            )
            if existing:
                existing.family_group = family
                existing.family_reason = reason
                existing.computed_at = datetime.utcnow()
            else:
                db.add(models.PackageFamilyGroup(
                    ait_id=ait_id, package=pkg,
                    family_group=family, family_reason=reason,
                ))
    db.commit()


def get_family_group_map(db: Session, ait_id: str) -> dict:
    """Returns {package: family_group} for all LLM-grouped packages in an AIT."""
    rows = (
        db.query(models.PackageFamilyGroup)
        .filter(models.PackageFamilyGroup.ait_id == ait_id)
        .all()
    )
    return {r.package: r.family_group for r in rows}
