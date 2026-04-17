from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SecureJobStatus = Literal[
    "PENDING",
    "RUNNING",
    "ANALYZING",
    "STRATEGY_GENERATING",
    "PATCH_GENERATING",
    "SAFETY_RECHECKING",
    "APPLYING_PATCH",
    "BUILDING_IMAGE",
    "COMPLETED",
    "FAILED",
    "UNSUPPORTED",
]
PatchStatus = Literal[
    "READY_FOR_RECHECK",
    "READY_FOR_BUILD",
    "READY_FOR_VALIDATION",
    "REJECTED",
]


class AttackInfo(BaseModel):
    category: str
    cwe_id: str
    cwe_name: str
    owasp_category: str
    payload_sample: str
    source_ip: str
    blocked: bool


class EndpointInfo(BaseModel):
    method: str
    path: str


class SourceMapping(BaseModel):
    file: str
    function: str
    line_start: int
    line_end: int


class TargetInfo(BaseModel):
    endpoint: EndpointInfo
    source_mapping: SourceMapping


class MetadataInfo(BaseModel):
    severity: Severity
    pipeline_version: str
    defense_action_taken: str
    requires_patch: bool


class RuntimeContextPackage(BaseModel):
    context_id: str
    event_id: str
    timestamp: datetime
    attack_info: AttackInfo
    target: TargetInfo
    metadata: MetadataInfo


class SecureCodingContextAcceptedResponse(BaseModel):
    job_id: str
    context_id: str
    event_id: str
    status: SecureJobStatus
    message: str


class SecureCodingJobResponse(BaseModel):
    job_id: str
    context_id: str
    event_id: str
    status: SecureJobStatus
    current_step: str
    progress: int
    created_at: str
    updated_at: str
    error: dict[str, Any] | None = None


class AnalysisFinding(BaseModel):
    rule_id: str
    file: str
    function: str
    line: int
    message: str
    severity: str


class AnalysisScope(BaseModel):
    primary_file: str
    primary_function: str
    line_start: int
    line_end: int
    related_files: list[str] = Field(default_factory=list)
    code_window: str | None = None


class VulnerabilityContext(BaseModel):
    source: str
    findings: list[AnalysisFinding]


class AnalyzeResponse(BaseModel):
    job_id: str
    step: str = "analyze"
    status: str
    analysis_scope: AnalysisScope
    vulnerability_context: VulnerabilityContext


class PatchStrategy(BaseModel):
    strategy_id: str
    root_cause: str
    fix_goal: str
    fix_actions: list[str]
    constraints: dict[str, Any]


class StrategyResponse(BaseModel):
    job_id: str
    step: str = "strategy"
    status: str
    strategy: PatchStrategy


class PatchPayload(BaseModel):
    patch_id: str
    target_file: str
    target_function: str
    patch_file: str
    unified_diff: str
    patch_status: PatchStatus
    change_summary: dict[str, Any]


class PatchResponse(BaseModel):
    job_id: str
    step: str = "patch"
    status: str
    patch: PatchPayload


class RecheckResult(BaseModel):
    syntax_valid: bool
    safety_checks_passed: bool
    remaining_findings: list[dict[str, Any]]
    patch_status: PatchStatus


class RecheckResponse(BaseModel):
    job_id: str
    step: str = "recheck"
    status: str
    recheck_result: RecheckResult


class ApplyResult(BaseModel):
    applied: bool
    mode: str
    workspace_file: str | None = None
    backup_file: str | None = None
    patch_status: PatchStatus


class ApplyResponse(BaseModel):
    job_id: str
    step: str = "apply"
    status: str
    apply_result: ApplyResult


class BuildResult(BaseModel):
    candidate_image: str
    build_log: str
    patch_status: PatchStatus


class BuildResponse(BaseModel):
    job_id: str
    step: str = "build"
    status: str
    build_result: BuildResult


class AnalysisSummary(BaseModel):
    root_cause: str
    fix_strategy: str


class SecureCodingResult(BaseModel):
    context_id: str
    event_id: str
    patch_id: str
    cwe_id: str
    target_file: str
    target_function: str
    patch_file: str
    candidate_image: str
    build_log: str | None = None
    analysis_summary: AnalysisSummary
    change_summary: dict[str, Any] | None = None
    workspace_file: str | None = None
    backup_file: str | None = None
    workspace_applied: bool | None = None
    patch_status: PatchStatus


class SecureCodingJobResultResponse(BaseModel):
    job_id: str
    context_id: str
    event_id: str
    status: SecureJobStatus
    result: SecureCodingResult


class SecureCodingRetryRequest(BaseModel):
    reason: str
    retry_from_step: str
    validation_feedback: dict[str, Any] = Field(default_factory=dict)


class PatchDetailResponse(BaseModel):
    patch_id: str
    event_id: str
    target_file: str
    target_function: str
    patch_file: str
    patch_status: PatchStatus
    unified_diff: str
    change_summary: dict[str, Any]


class HealthResponse(BaseModel):
    service: str
    status: str
