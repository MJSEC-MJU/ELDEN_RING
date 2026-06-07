from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


PatchStatus = Literal["READY_FOR_VALIDATION"]
ValidationJobStatus = Literal[
    "PENDING",
    "RUNNING",
    "DEPLOYING_ENVIRONMENT",
    "STARTUP_CHECKING",
    "REGRESSION_TESTING",
    "SECURITY_REPLAYING",
    "SLO_CHECKING",
    "COMPLETED",
    "FAILED",
    "CANCELED",
]
ValidationStageStatus = Literal["pass", "fail", "not_run"]


class AnalysisSummary(BaseModel):
    root_cause: str = ""
    fix_strategy: str = ""


class CandidateValidationRequest(BaseModel):
    job_id: str | None = None
    context_id: str
    event_id: str
    patch_id: str
    cwe_id: str
    target_file: str
    target_function: str
    patch_file: str
    candidate_image: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    build_log: str | None = None
    analysis_summary: AnalysisSummary = Field(default_factory=AnalysisSummary)
    change_summary: dict[str, Any] | None = None
    workspace_file: str | None = None
    backup_file: str | None = None
    workspace_applied: bool | None = None
    patch_status: PatchStatus


class ValidationAcceptedResponse(BaseModel):
    validation_job_id: str
    context_id: str
    event_id: str
    patch_id: str
    status: ValidationJobStatus
    message: str


class ValidationRerunRequest(BaseModel):
    reason: str
    rerun_from_stage: str = "DEPLOYING_ENVIRONMENT"


class ValidationStageResult(BaseModel):
    status: ValidationStageStatus
    summary: str = ""
    report_path: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)


class ValidationJobResponse(BaseModel):
    validation_job_id: str
    validation_result_id: str | None = None
    context_id: str
    event_id: str
    patch_id: str
    status: ValidationJobStatus
    current_stage: str | None = None
    progress: int = 0
    created_at: str
    updated_at: str
    error: dict[str, str | None] | None = None


class ValidationResultPayload(BaseModel):
    validation_result_id: str
    context_id: str
    event_id: str
    patch_id: str
    cwe_id: str
    candidate_image: str
    current_stable_image: str | None = None
    validation_result: dict[str, ValidationStageResult]
    selection_reason: str | None = None
    status: Literal["ready_for_governance", "failed"]
    next_action: str | None = None


class Phase3PromoteEnvelope(BaseModel):
    phase2: CandidateValidationRequest
    exploit: Literal["PASSED", "FAILED", "PENDING"]
    regression: Literal["PASSED", "FAILED", "PENDING"]
    slo: Literal["PASSED", "FAILED", "PENDING"]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    manifests: list[dict[str, Any]] = Field(default_factory=list)


class ValidationResultResponse(BaseModel):
    validation_job_id: str
    status: Literal["COMPLETED", "FAILED"]
    result: ValidationResultPayload


class HealthResponse(BaseModel):
    service: str = "recovery-assurance-plane"
    status: str = "healthy"


class RuntimeContext(BaseModel):
    attack_info: dict[str, Any] = Field(default_factory=dict)
    target: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
