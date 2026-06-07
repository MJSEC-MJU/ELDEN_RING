from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, FastAPI

from .config import PlaneSettings, load_settings
from .messaging import MessageBus
from .schemas import (
    ApplyResponse,
    AnalyzeResponse,
    BuildResponse,
    HealthResponse,
    PatchDetailResponse,
    PatchResponse,
    RecheckResponse,
    RuntimeContextPackage,
    SecureCodingContextAcceptedResponse,
    SecureCodingJobResponse,
    SecureCodingJobResultResponse,
    SecureCodingRetryRequest,
    StrategyResponse,
)
from .storage import PlaneStore
from .utils import dump_model, generate_id

from .service import SecureCodingService


def create_secure_coding_app(settings: PlaneSettings | None = None) -> FastAPI:
    settings = settings or load_settings()
    store = PlaneStore(settings.db_path)
    bus = MessageBus(settings, store)
    service = SecureCodingService(settings, store, bus)
    app = FastAPI(title="Secure Coding Plane")
    router = APIRouter(tags=["Secure Coding"])
    management_router = APIRouter(prefix="/api/v1/secure-coding", tags=["Secure Coding"])

    @router.post("/api/v1/context", response_model=SecureCodingContextAcceptedResponse, status_code=202)
    def ingest_runtime_context(request: RuntimeContextPackage, background_tasks: BackgroundTasks) -> SecureCodingContextAcceptedResponse:
        return service.submit_context(request, background_tasks)

    @management_router.get("/jobs/{job_id}", response_model=SecureCodingJobResponse)
    def get_secure_coding_job(job_id: str) -> SecureCodingJobResponse:
        return service.get_job_response(job_id)

    @management_router.get("/jobs/{job_id}/result", response_model=SecureCodingJobResultResponse)
    def get_secure_coding_result(job_id: str) -> SecureCodingJobResultResponse:
        return service.get_job_result(job_id)

    @management_router.post("/jobs/{job_id}/retry", status_code=202)
    def retry_secure_coding_job(job_id: str, request: SecureCodingRetryRequest, background_tasks: BackgroundTasks) -> dict[str, str]:
        return service.retry_job(job_id, request, background_tasks)

    @management_router.get("/patches/{patch_id}", response_model=PatchDetailResponse)
    def get_patch_detail(patch_id: str) -> PatchDetailResponse:
        return service.get_patch_detail(patch_id)

    @management_router.get("/health", response_model=HealthResponse)
    def get_health() -> HealthResponse:
        return service.health()

    @management_router.post("/internal/analyze", response_model=AnalyzeResponse)
    def internal_analyze(request: RuntimeContextPackage) -> AnalyzeResponse:
        return service.analysis_engine.run_analysis(generate_id("internal-job"), dump_model(request))

    @management_router.post("/internal/strategy", response_model=StrategyResponse)
    def internal_strategy(request: RuntimeContextPackage) -> StrategyResponse:
        return service.strategy_engine.run_strategy(generate_id("internal-job"), dump_model(request))

    @management_router.post("/internal/patch", response_model=PatchResponse)
    def internal_patch(request: RuntimeContextPackage) -> PatchResponse:
        job_id = generate_id("internal-job")
        context = dump_model(request)
        code_context = service.analysis_engine.load_code_context(context)
        strategy = service.strategy_engine.run_strategy(job_id, context).strategy
        return service.patch_engine.run_patch(job_id, context, strategy, code_context)

    @management_router.post("/internal/recheck", response_model=RecheckResponse)
    def internal_recheck(request: RuntimeContextPackage) -> RecheckResponse:
        job_id = generate_id("internal-job")
        context = dump_model(request)
        code_context = service.analysis_engine.load_code_context(context)
        strategy = service.strategy_engine.run_strategy(job_id, context).strategy
        patch = service.patch_engine.run_patch(job_id, context, strategy, code_context)
        return service.patch_engine.run_recheck(job_id, patch.patch.patch_id)

    @management_router.post("/internal/apply", response_model=ApplyResponse)
    def internal_apply(request: RuntimeContextPackage) -> ApplyResponse:
        job_id = generate_id("internal-job")
        context = dump_model(request)
        code_context = service.analysis_engine.load_code_context(context)
        strategy = service.strategy_engine.run_strategy(job_id, context).strategy
        patch = service.patch_engine.run_patch(job_id, context, strategy, code_context)
        recheck = service.patch_engine.run_recheck(job_id, patch.patch.patch_id)
        if not recheck.recheck_result.syntax_valid or not recheck.recheck_result.safety_checks_passed:
            raise RuntimeError("Safety recheck failed")
        return service.apply_engine.run_apply(job_id, patch.patch.patch_id)

    @management_router.post("/internal/build", response_model=BuildResponse)
    def internal_build(request: RuntimeContextPackage) -> BuildResponse:
        job_id = generate_id("internal-job")
        context = dump_model(request)
        code_context = service.analysis_engine.load_code_context(context)
        strategy = service.strategy_engine.run_strategy(job_id, context).strategy
        patch = service.patch_engine.run_patch(job_id, context, strategy, code_context).patch
        recheck = service.patch_engine.run_recheck(job_id, patch.patch_id)
        if not recheck.recheck_result.syntax_valid or not recheck.recheck_result.safety_checks_passed:
            raise RuntimeError("Safety recheck failed")
        service.apply_engine.run_apply(job_id, patch.patch_id)
        return service.build_engine.run_build(job_id, context, patch.patch_id, strategy)

    app.include_router(router)
    app.include_router(management_router)
    app.state.service = service
    app.state.store = store
    return app
