from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from .database import Base


class Application(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, index=True)
    ait_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    owner_email = Column(String(255))
    owner_name = Column(String(255))
    environment = Column(String(50), default="production")
    host = Column(String(255))
    dep_report = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

    findings = relationship("Finding", back_populates="application", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="application", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    ait_id = Column(String(50), ForeignKey("applications.ait_id"), nullable=False)
    scan_file = Column(Text)
    scan_time = Column(DateTime, default=datetime.utcnow)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)

    application = relationship("Application", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    ait_id = Column(String(50), ForeignKey("applications.ait_id"), nullable=False)
    cve_id = Column(String(50), nullable=False)
    package = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    installed_version = Column(String(255))
    fixed_version = Column(String(255))
    title = Column(Text)
    os_target = Column(String(255))
    # vulnerability = patchable CVE; npt = No-fix/Non-Patchable Treatment
    category = Column(String(50), default="vulnerability")
    # open | remediated | deferred | skipped | rolled_back
    status = Column(String(50), default="open")
    analysis_md = Column(Text)
    dep_note = Column(Text)
    # pending | ready | error
    plan_status = Column(String(50), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    application = relationship("Application", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    remediation_plan = relationship(
        "RemediationPlan", back_populates="finding",
        uselist=False, cascade="all, delete-orphan"
    )
    actions = relationship("RemediationAction", back_populates="finding", cascade="all, delete-orphan")
    approvals = relationship("Approval", back_populates="finding", cascade="all, delete-orphan")


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), unique=True, nullable=False)
    action = Column(String(50))
    package = Column(String(255))
    reboot_required = Column(Boolean, default=False)
    services_to_restart = Column(Text, default="")   # comma-separated
    reason = Column(Text)
    restore_plan = Column(Text)
    plan_json = Column(JSON)
    plan_error = Column(Text)
    generated_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="remediation_plan")


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    ait_id = Column(String(50), ForeignKey("applications.ait_id"), nullable=False)
    # remediate | defer | skip | rollback
    action_type = Column(String(50), nullable=False)
    performed_by = Column(String(255), default="web-ui")
    ansible_output = Column(Text)
    success = Column(Boolean)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="actions")


class Approval(Base):
    __tablename__ = "approvals"
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    ait_id = Column(String(50), ForeignKey("applications.ait_id"), nullable=False)
    # rollback | remediate
    approval_type = Column(String(50), nullable=False)
    token = Column(String(255), unique=True, index=True)
    # pending | approved | rejected
    status = Column(String(50), default="pending")
    approver_email = Column(String(255))
    notes = Column(Text)
    requested_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime)

    finding = relationship("Finding", back_populates="approvals")


class PackageFamilyGroup(Base):
    """LLM-computed family groupings: maps each package to its logical family."""
    __tablename__ = "package_family_groups"
    __table_args__ = (UniqueConstraint("ait_id", "package", name="uq_pfg_ait_package"),)

    id = Column(Integer, primary_key=True, index=True)
    ait_id = Column(String(50), nullable=False, index=True)
    package = Column(String(255), nullable=False)
    family_group = Column(String(255), nullable=False)
    family_reason = Column(Text)
    computed_at = Column(DateTime, default=datetime.utcnow)
