from __future__ import annotations

from typing import Any

from fastapi import BackgroundTasks, HTTPException

from .config import PlaneSettings
from .messaging import MessageBus
from .schemas import (
    ApplyResponse,
    AnalysisSummary,
    BuildResult,
    HealthResponse,
    PatchDetailResponse,
    PatchPayload,
    PatchStrategy,
    RuntimeContextPackage,
    SecureCodingContextAcceptedResponse,
    SecureCodingJobResponse,
    SecureCodingJobResultResponse,
    SecureCodingRetryRequest,
)
from .storage import PlaneStore
from .utils import dump_model, generate_id

from .apply import SecureCodingApplyEngine
from .analysis import SecureCodingAnalysisEngine
from .build import SecureCodingBuildEngine
from .constants import SUPPORTED_CWE
from .patching import SecureCodingPatchEngine
from .strategy import SecureCodingStrategyEngine


class SecureCodingService:
    def __init__(self, settings: PlaneSettings, store: PlaneStore, bus: MessageBus) -> None:
        self.settings = settings
        self.store = store
        self.bus = bus
        self.artifact_root = settings.artifact_root / "secure_coding"
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.analysis_engine = SecureCodingAnalysisEngine(settings, store, self.artifact_root)
        self.strategy_engine = SecureCodingStrategyEngine(store, self.artifact_root)
        self.patch_engine = SecureCodingPatchEngine(settings, store, self.artifact_root)
        self.apply_engine = SecureCodingApplyEngine(settings, store, self.artifact_root)
        self.build_engine = SecureCodingBuildEngine(settings, store, self.artifact_root)

    @classmethod
    def from_settings(cls, settings: PlaneSettings, store: PlaneStore | None = None) -> "SecureCodingService":
        local_store = store or PlaneStore(settings.db_path)
        bus = MessageBus(settings, local_store)
        return cls(settings, local_store, bus)

    def submit_context(self, context: RuntimeContextPackage, background_tasks: BackgroundTasks) -> SecureCodingContextAcceptedResponse:
        accepted, payload = self._accept_context(context)
        background_tasks.add_task(self.process_job, accepted.job_id, payload)
        return accepted

    def submit_context_sync(self, context: RuntimeContextPackage) -> SecureCodingContextAcceptedResponse:
        accepted, payload = self._accept_context(context)
        self.process_job(accepted.job_id, payload)
        return accepted

    def _accept_context(self, context: RuntimeContextPackage) -> tuple[SecureCodingContextAcceptedResponse, dict[str, Any]]:
        if not context.metadata.requires_patch:
            raise HTTPException(status_code=400, detail="Patch not required")
        if context.attack_info.cwe_id not in SUPPORTED_CWE:
            raise HTTPException(status_code=422, detail="Unsupported CWE for current PoC")
        if context.target.source_mapping.line_start <= 0 or context.target.source_mapping.line_end < context.target.source_mapping.line_start:
            raise HTTPException(status_code=422, detail="Invalid line range")
        if self.store.get_secure_job_by_event(context.event_id):
            raise HTTPException(status_code=409, detail="Duplicate secure coding job for event_id")

        job_id = generate_id("sc-job")
        payload = dump_model(context)
        self.store.save_runtime_context(payload)
        self.store.create_secure_job(
            job_id=job_id,
            context_id=context.context_id,
            event_id=context.event_id,
            cwe_id=context.attack_info.cwe_id,
            status="PENDING",
            current_step="context_validation",
            progress=0,
        )
        return (
            SecureCodingContextAcceptedResponse(
                job_id=job_id,
                context_id=context.context_id,
                event_id=context.event_id,
                status="PENDING",
                message="Secure coding context accepted",
            ),
            payload,
        )

    def process_job(self, job_id: str, context: dict[str, Any]) -> None:
        applied_patch_id: str | None = None
        try:
            self.store.update_secure_job(job_id, status="RUNNING", current_step="context_validation", progress=5)
            code_context = self.analysis_engine.load_code_context(context)
            self.analysis_engine.run_analysis(job_id, context)
            strategy_result = self.strategy_engine.run_strategy(job_id, context)
            patch_result = self.patch_engine.run_patch(job_id, context, strategy_result.strategy, code_context)
            recheck_result = self.patch_engine.run_recheck(job_id, patch_result.patch.patch_id)
            if not recheck_result.recheck_result.syntax_valid or not recheck_result.recheck_result.safety_checks_passed:
                raise RuntimeError("Safety recheck failed")
            self.apply_engine.run_apply(job_id, patch_result.patch.patch_id)
            applied_patch_id = patch_result.patch.patch_id
            patch_row = self.store.get_secure_patch(patch_result.patch.patch_id)
            if not patch_row:
                raise RuntimeError("Applied patch metadata not found")
            build_result = self.build_engine.run_build(job_id, context, patch_result.patch.patch_id, strategy_result.strategy)
            result = self._compose_result(
                job_id,
                context,
                PatchPayload(
                    patch_id=patch_row["patch_id"],
                    target_file=patch_row["target_file"],
                    target_function=patch_row["target_function"],
                    patch_file=patch_row["patch_file"],
                    unified_diff=patch_row["unified_diff"],
                    patch_status=patch_row["patch_status"],
                    change_summary=patch_row["change_summary_json"],
                ),
                build_result.build_result,
                strategy_result.strategy,
            )
            self.bus.publish(self.settings.secure_coding_validate_channel, dump_model(result.result))
            self.store.update_secure_job(job_id, status="COMPLETED", current_step="publish_validate", progress=100)
        except Exception as exc:
            if applied_patch_id and self.settings.secure_coding_apply_rollback_on_failure:
                try:
                    self.apply_engine.rollback_apply(job_id, applied_patch_id)
                except Exception:
                    pass
            self.store.update_secure_job(
                job_id,
                status="FAILED",
                current_step="failed",
                progress=100,
                error_code=type(exc).__name__,
                error_message=str(exc),
            )

    def retry_job(self, job_id: str, request: SecureCodingRetryRequest, background_tasks: BackgroundTasks) -> dict[str, str]:
        context = self._prepare_retry(job_id, request)
        background_tasks.add_task(self.process_job, job_id, context)
        return {"job_id": job_id, "status": "PENDING", "message": "Retry accepted"}

    def retry_job_sync(self, job_id: str, request: SecureCodingRetryRequest) -> dict[str, str]:
        context = self._prepare_retry(job_id, request)
        self.process_job(job_id, context)
        return {"job_id": job_id, "status": "PENDING", "message": "Retry accepted"}

    def _prepare_retry(self, job_id: str, request: SecureCodingRetryRequest) -> dict[str, Any]:
        job = self.store.get_secure_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown job_id")
        context = self.store.get_runtime_context(job["context_id"])
        if not context:
            raise HTTPException(status_code=404, detail="Runtime context not found")
        self.store.save_secure_retry_request(
            retry_id=generate_id("retry"),
            job_id=job_id,
            retry_from_step=request.retry_from_step,
            reason=request.reason,
            validation_feedback=request.validation_feedback,
        )
        self.store.update_secure_job(job_id, status="PENDING", current_step=request.retry_from_step, progress=0)
        return context

    def get_job_response(self, job_id: str) -> SecureCodingJobResponse:
        row = self.store.get_secure_job(job_id)
        if not row:
            raise HTTPException(status_code=404, detail="Unknown job_id")
        error = None if not row["error_code"] and not row["error_message"] else {"code": row["error_code"], "message": row["error_message"]}
        return SecureCodingJobResponse(
            job_id=row["job_id"],
            context_id=row["context_id"],
            event_id=row["event_id"],
            status=row["status"],
            current_step=row["current_step"],
            progress=row["progress"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            error=error,
        )

    def get_job_result(self, job_id: str) -> SecureCodingJobResultResponse:
        row = self.store.get_secure_job(job_id)
        if not row:
            raise HTTPException(status_code=404, detail="Unknown job_id")
        if row["status"] != "COMPLETED":
            raise HTTPException(status_code=409, detail="Secure coding job not completed")
        patch = self.store.get_secure_patch_by_job(job_id)
        build = self.store.get_secure_build_by_job(job_id)
        strategy = self.store.get_secure_strategy(job_id)
        context = self.store.get_runtime_context(row["context_id"])
        if not patch or not build or not strategy or not context:
            raise HTTPException(status_code=500, detail="Secure coding artifacts incomplete")
        return self._compose_result(
            job_id,
            context,
            PatchPayload(
                patch_id=patch["patch_id"],
                target_file=patch["target_file"],
                target_function=patch["target_function"],
                patch_file=patch["patch_file"],
                unified_diff=patch["unified_diff"],
                patch_status=patch["patch_status"],
                change_summary=patch["change_summary_json"],
            ),
            BuildResult(
                candidate_image=build["candidate_image"],
                build_log=build["build_log"],
                patch_status="READY_FOR_VALIDATION",
            ),
            PatchStrategy(**strategy),
        )

    def get_patch_detail(self, patch_id: str) -> PatchDetailResponse:
        row = self.store.get_secure_patch(patch_id)
        if not row:
            raise HTTPException(status_code=404, detail="Unknown patch_id")
        return PatchDetailResponse(
            patch_id=row["patch_id"],
            event_id=row["event_id"],
            target_file=row["target_file"],
            target_function=row["target_function"],
            patch_file=row["patch_file"],
            patch_status=row["patch_status"],
            unified_diff=row["unified_diff"],
            change_summary=row["change_summary_json"],
        )

    def health(self) -> HealthResponse:
        return HealthResponse(service="secure-coding-plane", status="healthy")

    def apply_patch(self, job_id: str, patch_id: str) -> ApplyResponse:
        return self.apply_engine.run_apply(job_id, patch_id)

    def _compose_result(
        self,
        job_id: str,
        context: dict[str, Any],
        patch: PatchPayload,
        build: BuildResult,
        strategy: PatchStrategy,
    ) -> SecureCodingJobResultResponse:
        return SecureCodingJobResultResponse(
            job_id=job_id,
            context_id=context["context_id"],
            event_id=context["event_id"],
            status="COMPLETED",
            result={
                "job_id": job_id,
                "context_id": context["context_id"],
                "event_id": context["event_id"],
                "patch_id": patch.patch_id,
                "cwe_id": context["attack_info"]["cwe_id"],
                "target_file": patch.target_file,
                "target_function": patch.target_function,
                "patch_file": patch.patch_file,
                "candidate_image": build.candidate_image,
                "severity": context["metadata"]["severity"],
                "build_log": build.build_log,
                "analysis_summary": AnalysisSummary(
                    root_cause=strategy.root_cause,
                    fix_strategy=strategy.fix_actions[0],
                ),
                "change_summary": patch.change_summary,
                "workspace_file": patch.change_summary.get("workspace_file"),
                "backup_file": patch.change_summary.get("backup_file"),
                "workspace_applied": patch.change_summary.get("workspace_applied"),
                "patch_status": build.patch_status,
            },
        )
