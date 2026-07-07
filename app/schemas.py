from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ApplicationCreate(BaseModel):
    ait_id: str
    name: str
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    environment: Optional[str] = "production"
    host: Optional[str] = None


class ApprovalCreate(BaseModel):
    approval_type: str = "rollback"
    approver_email: Optional[str] = None


class ApprovalAction(BaseModel):
    notes: Optional[str] = None
    approver_email: Optional[str] = None


class BulkRemediateRequest(BaseModel):
    finding_ids: list[int]


class AnalyzeRequest(BaseModel):
    finding_ids: Optional[list[int]] = None


class DepCheckRequest(BaseModel):
    live: bool = False
