from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
PatchStatus = Literal[
    "READY_FOR_RECHECK",
    "READY_FOR_BUILD",
    "READY_FOR_VALIDATION",
    "REJECTED",
]


class Phase2AnalysisSummary(BaseModel):
    root_cause: str
    fix_strategy: str


class Phase2Result(BaseModel):
    job_id: str | None = None
    context_id: str
    event_id: str
    patch_id: str
    cwe_id: str
    target_file: str
    target_function: str
    patch_file: str
    candidate_image: str
    severity: Severity | None = None
    build_log: str | None = None
    analysis_summary: Phase2AnalysisSummary
    change_summary: dict[str, Any] | None = None
    workspace_file: str | None = None
    backup_file: str | None = None
    workspace_applied: bool | None = None
    patch_status: PatchStatus


class Phase3PromoteEnvelope(BaseModel):
    phase2: Phase2Result
    exploit: Literal["PASSED", "FAILED", "PENDING"]
    regression: Literal["PASSED", "FAILED", "PENDING"]
    slo: Literal["PASSED", "FAILED", "PENDING"]
    severity: Severity = "MEDIUM"
    manifests: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return self.exploit == "PASSED" and self.regression == "PASSED" and self.slo == "PASSED"
