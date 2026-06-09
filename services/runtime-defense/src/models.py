"""Pydantic schemas for the runtime-defense event pipeline."""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class TargetEndpoint(BaseModel):
    method: str = "UNKNOWN"
    path: str = "UNKNOWN"


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source: str  # "modsecurity", "falco", "manual"
    attack_category: str
    target_endpoint: TargetEndpoint
    payload_sample: str = ""
    source_ip: Optional[str] = None
    blocked: bool = False
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    raw_rule_id: Optional[str] = None
    requires_patch: Optional[bool] = None
    defense_action_taken: Optional[str] = None


class ManualEventRequest(BaseModel):
    """Schema for the manual event injection endpoint."""
    source: str = "manual"
    attack_category: str
    target_endpoint: TargetEndpoint
    payload_sample: str = ""
    source_ip: Optional[str] = None
    severity: str = "MEDIUM"
    blocked: bool = False
    requires_patch: Optional[bool] = None
    defense_action_taken: Optional[str] = None
