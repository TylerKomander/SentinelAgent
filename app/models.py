import time
import uuid
from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal[
    "new", "triaging", "triaged", "remediating", "remediated", "error"
]


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    source: str = "demo"
    ts: float = Field(default_factory=time.time)
    severity: Severity = "medium"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    summary: str = ""
    raw: dict = Field(default_factory=dict)


class Verdict(BaseModel):
    severity: Severity
    category: str = "uncategorized"
    disposition: Literal["actionable", "benign"] = "actionable"
    root_cause: str
    suggested_fix: str
    proposed_action: Optional[str] = None
    action_evidence: Optional[str] = None
    action_verified: Optional[bool] = None
    confidence: Literal["low", "medium", "high"] = "medium"


class AlertRecord(BaseModel):
    alert: Alert
    count: int = 1
    last_ts: float = Field(default_factory=time.time)
    status: Status = "new"
    verdict: Optional[Verdict] = None
    recon_log: list = Field(default_factory=list)
    observed_ips: list = Field(default_factory=list)
    error: Optional[str] = None
    remediation: Optional[dict] = None
    report_path: Optional[str] = None
