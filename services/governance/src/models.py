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

    @property
    def all_passed(self) -> bool:
        return (
            self.exploit == ValidationStatus.PASSED
            and self.regression == ValidationStatus.PASSED
            and self.slo == ValidationStatus.PASSED
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
