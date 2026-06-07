from __future__ import annotations

from typing import Any

from fastapi import BackgroundTasks, HTTPException

from .config import Settings
from .constants import REQUIRED_STAGES, SUPPORTED_CWE
from .messaging import MessageBus
from .models import (
    CandidateValidationRequest,
    HealthResponse,
    Phase3PromoteEnvelope,
    ValidationAcceptedResponse,
    ValidationJobResponse,
    ValidationResultPayload,
    ValidationResultResponse,
    ValidationRerunRequest,
    ValidationStageResult,
)
from .stages import ValidationStages
from .store import JsonStore
from .utils import dump_json, generate_id, now_iso, write_json


class RecoveryAssuranceService:
    def __init__(self, settings: Settings, store: JsonStore, bus: MessageBus) -> None:
        self.settings = settings
        self.store = store
        self.bus = bus
        self.stages = ValidationStages(settings, store)

    def submit_validation(
        self,
        request: CandidateValidationRequest,
        background_tasks: BackgroundTasks,
    ) -> ValidationAcceptedResponse:
        if request.patch_status != "READY_FOR_VALIDATION":
            raise HTTPException(status_code=400, detail="Patch is not ready for validation")
        if request.cwe_id not in SUPPORTED_CWE:
            raise HTTPException(status_code=422, detail="Unsupported CWE for current PoC")
        if self.store.get_job_by_patch(request.patch_id):
            raise HTTPException(status_code=409, detail="Duplicate validation job for patch_id")

        validation_job_id = generate_id("ra-job")
        now = now_iso()
        self.store.create_job(
            {
                "validation_job_id": validation_job_id,
                "validation_result_id": None,
                "context_id": request.context_id,
                "event_id": request.event_id,
                "patch_id": request.patch_id,
                "cwe_id": request.cwe_id,
                "candidate_image": request.candidate_image,
                "stable_image": self.settings.stable_image,
                "candidate_payload": dump_json(request),
                "status": "PENDING",
                "current_stage": "queued",
                "progress": 0,
                "selection_reason": None,
                "error_code": None,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            }
        )
        background_tasks.add_task(self.process_validation, validation_job_id, dump_json(request))
        return ValidationAcceptedResponse(
            validation_job_id=validation_job_id,
            context_id=request.context_id,
            event_id=request.event_id,
            patch_id=request.patch_id,
            status="PENDING",
            message="Recovery validation request accepted",
        )

    def process_validation(self, validation_job_id: str, request: dict[str, Any]) -> None:
        self.store.update_job(validation_job_id, status="RUNNING", current_stage="run", updated_at=now_iso())
        stage_results: dict[str, ValidationStageResult] = {}
        try:
            runtime_context = self.store.get_runtime_context(request["context_id"])
            self.stages.deploy(validation_job_id, request["candidate_image"])

            startup = self.stages.startup_check(validation_job_id, request)
            stage_results["startup"] = startup
            if startup.status != "pass":
                self._fail(validation_job_id, request, "startup", startup, stage_results)
                return

            regression = self.stages.regression_test(validation_job_id, request)
            stage_results["regression"] = regression
            if regression.status != "pass":
                self._fail(validation_job_id, request, "regression", regression, stage_results)
                return

            security_replay = self.stages.security_replay(validation_job_id, request, runtime_context)
            stage_results["security_replay"] = security_replay
            if security_replay.status != "pass":
                self._fail(validation_job_id, request, "security_replay", security_replay, stage_results)
                return

            slo = self.stages.slo_check(validation_job_id, request)
            stage_results["slo"] = slo
            if slo.status != "pass":
                self._fail(validation_job_id, request, "slo", slo, stage_results)
                return

            result = self._success_result(validation_job_id, request, stage_results)
            envelope = self._promote_envelope(request, stage_results)
            write_json(self.settings.artifact_dir / "final" / f"{validation_job_id}.json", dump_json(result))
            self.bus.publish(self.settings.promote_channel, dump_json(envelope))
            self.stages.cleanup(validation_job_id)
            self.store.update_job(
                validation_job_id,
                validation_result_id=result.result.validation_result_id,
                status="COMPLETED",
                current_stage="finalize",
                progress=100,
                selection_reason=result.result.selection_reason,
                updated_at=now_iso(),
            )
        except Exception as exc:
            self.stages.cleanup(validation_job_id)
            self.store.update_job(
                validation_job_id,
                status="FAILED",
                current_stage="failed",
                progress=100,
                error_code=type(exc).__name__,
                error_message=str(exc),
                updated_at=now_iso(),
            )

    def get_validation_job(self, validation_job_id: str) -> ValidationJobResponse:
        job = self.store.get_job(validation_job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown validation_job_id")
        error = None
        if job.get("error_code") or job.get("error_message"):
            error = {"code": job.get("error_code"), "message": job.get("error_message")}
        return ValidationJobResponse(
            validation_job_id=job["validation_job_id"],
            validation_result_id=job.get("validation_result_id"),
            context_id=job["context_id"],
            event_id=job["event_id"],
            patch_id=job["patch_id"],
            status=job["status"],
            current_stage=job.get("current_stage"),
            progress=job.get("progress", 0),
            created_at=job["created_at"],
            updated_at=job["updated_at"],
            error=error,
        )

    def get_validation_result(self, validation_job_id: str) -> ValidationResultResponse:
        job = self.store.get_job(validation_job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown validation_job_id")
        if job["status"] not in {"COMPLETED", "FAILED"}:
            raise HTTPException(status_code=409, detail="Validation job not completed")
        stage_results = self._stage_results(validation_job_id)
        return ValidationResultResponse(
            validation_job_id=validation_job_id,
            status="COMPLETED" if job["status"] == "COMPLETED" else "FAILED",
            result=ValidationResultPayload(
                validation_result_id=job.get("validation_result_id") or generate_id("val"),
                context_id=job["context_id"],
                event_id=job["event_id"],
                patch_id=job["patch_id"],
                cwe_id=job["cwe_id"],
                candidate_image=job["candidate_image"],
                current_stable_image=job.get("stable_image"),
                validation_result=stage_results,
                selection_reason=job.get("selection_reason"),
                status="ready_for_governance" if job["status"] == "COMPLETED" else "failed",
                next_action=None if job["status"] == "COMPLETED" else "request_secure_coding_retry",
            ),
        )

    def rerun_validation(
        self,
        validation_job_id: str,
        request: ValidationRerunRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, str]:
        job = self.store.get_job(validation_job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown validation_job_id")
        self.store.update_job(
            validation_job_id,
            status="PENDING",
            current_stage=request.rerun_from_stage,
            progress=0,
            error_code=None,
            error_message=None,
            updated_at=now_iso(),
        )
        background_tasks.add_task(self.process_validation, validation_job_id, job["candidate_payload"])
        return {"validation_job_id": validation_job_id, "status": "PENDING", "message": "Validation rerun accepted"}

    def health(self) -> HealthResponse:
        return HealthResponse()

    def inject_runtime_context(self, context_id: str, payload: dict[str, Any]) -> dict[str, str]:
        self.store.save_runtime_context(context_id, payload)
        return {"context_id": context_id, "status": "stored"}

    def _success_result(
        self,
        validation_job_id: str,
        request: dict[str, Any],
        stage_results: dict[str, ValidationStageResult],
    ) -> ValidationResultResponse:
        return ValidationResultResponse(
            validation_job_id=validation_job_id,
            status="COMPLETED",
            result=ValidationResultPayload(
                validation_result_id=generate_id("val"),
                context_id=request["context_id"],
                event_id=request["event_id"],
                patch_id=request["patch_id"],
                cwe_id=request["cwe_id"],
                candidate_image=request["candidate_image"],
                current_stable_image=self.settings.stable_image,
                validation_result=stage_results,
                selection_reason="first_candidate_passing_all_required_checks",
                status="ready_for_governance",
            ),
        )

    def _fail(
        self,
        validation_job_id: str,
        request: dict[str, Any],
        failed_stage: str,
        failed_result: ValidationStageResult,
        stage_results: dict[str, ValidationStageResult],
    ) -> None:
        for stage in REQUIRED_STAGES:
            stage_results.setdefault(stage, ValidationStageResult(status="not_run"))
        validation_result_id = generate_id("val")
        retry_from_step = {
            "startup": "PATCH_GENERATING",
            "regression": "STRATEGY_GENERATING",
            "security_replay": "STRATEGY_GENERATING",
            "slo": "PATCH_GENERATING",
        }[failed_stage]
        result = ValidationResultResponse(
            validation_job_id=validation_job_id,
            status="FAILED",
            result=ValidationResultPayload(
                validation_result_id=validation_result_id,
                context_id=request["context_id"],
                event_id=request["event_id"],
                patch_id=request["patch_id"],
                cwe_id=request["cwe_id"],
                candidate_image=request["candidate_image"],
                current_stable_image=self.settings.stable_image,
                validation_result=stage_results,
                status="failed",
                next_action="request_secure_coding_retry",
            ),
        )
        feedback = {
            "job_id": request.get("job_id"),
            "event_id": request["event_id"],
            "incident_id": request["event_id"],
            "patch_id": request["patch_id"],
            "phase2": self._phase2_payload(request),
            "reason": "retry_after_validation_failure",
            "retry_from_step": retry_from_step,
            "validation_feedback": {
                "failed_stage": failed_stage,
                "summary": failed_result.summary,
                "validation_result_id": validation_result_id,
                "metrics": failed_result.metrics,
            },
        }
        write_json(self.settings.artifact_dir / "final" / f"{validation_job_id}.json", dump_json(result))
        self.bus.publish(self.settings.retry_channel, feedback)
        self.stages.cleanup(validation_job_id)
        self.store.update_job(
            validation_job_id,
            validation_result_id=validation_result_id,
            status="FAILED",
            current_stage=failed_stage,
            progress=100,
            error_code=f"{failed_stage.upper()}_FAILED",
            error_message=failed_result.summary,
            updated_at=now_iso(),
        )

    def _stage_results(self, validation_job_id: str) -> dict[str, ValidationStageResult]:
        raw = self.store.get_stages(validation_job_id)
        stages = {
            name: ValidationStageResult(**payload)
            for name, payload in raw.items()
        }
        for stage in REQUIRED_STAGES:
            stages.setdefault(stage, ValidationStageResult(status="not_run"))
        return stages

    def _promote_envelope(
        self,
        request: dict[str, Any],
        stage_results: dict[str, ValidationStageResult],
    ) -> Phase3PromoteEnvelope:
        return Phase3PromoteEnvelope(
            phase2=CandidateValidationRequest(**self._phase2_payload(request)),
            exploit=self._to_phase4_status(stage_results["security_replay"]),
            regression=self._to_phase4_status(stage_results["regression"]),
            slo=self._to_phase4_status(stage_results["slo"]),
            severity=request.get("severity") or "MEDIUM",
        )

    def _phase2_payload(self, request: dict[str, Any]) -> dict[str, Any]:
        return {
            "job_id": request.get("job_id"),
            "context_id": request["context_id"],
            "event_id": request["event_id"],
            "patch_id": request["patch_id"],
            "cwe_id": request["cwe_id"],
            "target_file": request["target_file"],
            "target_function": request["target_function"],
            "patch_file": request["patch_file"],
            "candidate_image": request["candidate_image"],
            "severity": request.get("severity"),
            "build_log": request.get("build_log"),
            "analysis_summary": request.get("analysis_summary") or {},
            "change_summary": request.get("change_summary"),
            "workspace_file": request.get("workspace_file"),
            "backup_file": request.get("backup_file"),
            "workspace_applied": request.get("workspace_applied"),
            "patch_status": request["patch_status"],
        }

    def _to_phase4_status(self, result: ValidationStageResult) -> str:
        if result.status == "pass":
            return "PASSED"
        if result.status == "fail":
            return "FAILED"
        return "PENDING"
