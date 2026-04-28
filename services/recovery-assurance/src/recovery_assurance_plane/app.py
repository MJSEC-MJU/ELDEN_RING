from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, FastAPI

from .config import Settings, load_settings
from .messaging import MessageBus
from .models import (
    CandidateValidationRequest,
    HealthResponse,
    ValidationAcceptedResponse,
    ValidationJobResponse,
    ValidationResultResponse,
    ValidationRerunRequest,
)
from .service import RecoveryAssuranceService
from .store import JsonStore


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    store = JsonStore(settings.data_dir)
    bus = MessageBus(settings, store)
    service = RecoveryAssuranceService(settings, store, bus)

    app = FastAPI(title="Recovery Assurance Plane", version="0.1.0")
    router = APIRouter(prefix="/api/v1/recovery-assurance", tags=["Recovery Assurance"])

    @router.post("/validate", response_model=ValidationAcceptedResponse, status_code=202)
    def validate_candidate(
        request: CandidateValidationRequest,
        background_tasks: BackgroundTasks,
    ) -> ValidationAcceptedResponse:
        return service.submit_validation(request, background_tasks)

    @router.get("/jobs/{validation_job_id}", response_model=ValidationJobResponse)
    def get_validation_job(validation_job_id: str) -> ValidationJobResponse:
        return service.get_validation_job(validation_job_id)

    @router.get("/jobs/{validation_job_id}/result", response_model=ValidationResultResponse)
    def get_validation_result(validation_job_id: str) -> ValidationResultResponse:
        return service.get_validation_result(validation_job_id)

    @router.post("/jobs/{validation_job_id}/rerun", status_code=202)
    def rerun_validation_job(
        validation_job_id: str,
        request: ValidationRerunRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, str]:
        return service.rerun_validation(validation_job_id, request, background_tasks)

    @router.get("/health", response_model=HealthResponse)
    def get_health() -> HealthResponse:
        return service.health()

    @router.post("/runtime-contexts/{context_id}", include_in_schema=False)
    def put_runtime_context(context_id: str, payload: dict[str, Any]) -> dict[str, str]:
        return service.inject_runtime_context(context_id, payload)

    @router.post("/internal/deploy")
    def internal_deploy(payload: dict[str, Any]) -> dict[str, Any]:
        validation_job_id = payload.get("validation_job_id", "internal-ra-job")
        candidate_image = payload.get("candidate_image", "")
        return service.stages.deploy(validation_job_id, candidate_image)

    @router.post("/internal/startup-check")
    def internal_startup_check(payload: dict[str, Any]) -> dict[str, Any]:
        validation_job_id = payload.get("validation_job_id", "internal-ra-job")
        candidate_image = payload.get("candidate_image", "")
        return service.stages.startup_check(validation_job_id, candidate_image).model_dump(mode="json")

    @router.post("/internal/regression-test")
    def internal_regression_test(payload: dict[str, Any]) -> dict[str, Any]:
        validation_job_id = payload.get("validation_job_id", "internal-ra-job")
        candidate_image = payload.get("candidate_image", "")
        return service.stages.regression_test(validation_job_id, candidate_image).model_dump(mode="json")

    @router.post("/internal/security-replay")
    def internal_security_replay(payload: dict[str, Any]) -> dict[str, Any]:
        validation_job_id = payload.get("validation_job_id", "internal-ra-job")
        runtime_context = payload.get("runtime_context")
        request = {
            "context_id": payload.get("context_id", ""),
            "patch_id": payload.get("patch_id", ""),
            "cwe_id": payload.get("cwe_id", payload.get("attack_info", {}).get("cwe_id", "")),
            "patch_file": payload.get("patch_file"),
            "candidate_image": payload.get("candidate_image", ""),
        }
        return service.stages.security_replay(validation_job_id, request, runtime_context).model_dump(mode="json")

    @router.post("/internal/slo-check")
    def internal_slo_check(payload: dict[str, Any]) -> dict[str, Any]:
        validation_job_id = payload.get("validation_job_id", "internal-ra-job")
        request = {
            "patch_file": payload.get("patch_file"),
            "candidate_image": payload.get("candidate_image", ""),
        }
        return service.stages.slo_check(validation_job_id, request).model_dump(mode="json")

    @router.post("/internal/finalize")
    def internal_finalize(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "validation_job_id": payload.get("validation_job_id", "internal-ra-job"),
            "step": "finalize",
            "status": "success",
        }

    app.include_router(router)
    app.state.settings = settings
    app.state.store = store
    app.state.service = service
    return app
