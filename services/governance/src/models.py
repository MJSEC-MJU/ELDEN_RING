from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class RiskClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ValidationStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    PENDING = "PENDING"


class PromotionStage(str, Enum):
    POLICY_CHECK = "policy_check"
    GIT_PR = "git_pr"
    SHADOW_SYNC = "shadow_sync"
    CANARY_ANALYSIS = "canary_analysis"
    MANUAL_APPROVAL = "manual_approval"
    PROD_SYNC = "prod_sync"
    ROLLED_BACK = "rolled_back"
    COMPLETED = "completed"


class Phase3Result(BaseModel):
    incident_id: str
    candidate_image: str
    exploit: ValidationStatus
    regression: ValidationStatus
    slo: ValidationStatus
    manifests: list[dict[str, Any]] = Field(default_factory=list)

    event_id: str | None = None
    patch_id: str | None = None
    cwe_id: str | None = None
    target_file: str | None = None
    target_function: str | None = None
    change_summary: dict[str, Any] | None = None
    severity: str | None = None

    @property
    def all_passed(self) -> bool:
        return (
            self.exploit == ValidationStatus.PASSED
            and self.regression == ValidationStatus.PASSED
            and self.slo == ValidationStatus.PASSED
        )

    @classmethod
    def parse(cls, payload: dict[str, Any]) -> "Phase3Result":
        if "phase2" in payload:
            return cls.from_envelope(payload)
        return cls(**payload)

    @classmethod
    def from_envelope(cls, payload: dict[str, Any]) -> "Phase3Result":
        p2 = payload["phase2"]
        return cls(
            incident_id=p2["event_id"],
            candidate_image=p2["candidate_image"],
            exploit=ValidationStatus(payload["exploit"]),
            regression=ValidationStatus(payload["regression"]),
            slo=ValidationStatus(payload["slo"]),
            manifests=payload.get("manifests", []),
            event_id=p2["event_id"],
            patch_id=p2["patch_id"],
            cwe_id=p2["cwe_id"],
            target_file=p2["target_file"],
            target_function=p2["target_function"],
            change_summary=p2.get("change_summary"),
            severity=payload.get("severity"),
        )


class PromotionRequest(BaseModel):
    incident_id: str
    risk: RiskClass
    stage: PromotionStage
    branch: str
    pr_number: int | None = None
    rollout_name: str = "target-app"
    rollout_namespace: str = "elden-canary"
    reason: str = ""


class PolicyGateResult(BaseModel):
    passed: bool
    violations: list[str] = Field(default_factory=list)
    policy_reports: list[str] = Field(default_factory=list)
