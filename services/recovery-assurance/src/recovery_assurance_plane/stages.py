from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import Settings
from .llm_validation import create_validation_client
from .models import ValidationStageResult
from .store import JsonStore
from .utils import dump_json, now_iso, write_json


class ValidationStages:
    def __init__(self, settings: Settings, store: JsonStore) -> None:
        self.settings = settings
        self.store = store
        self.artifact_dir = settings.artifact_dir
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.validation_client = create_validation_client(settings)

    def deploy(self, validation_job_id: str, candidate_image: str) -> dict[str, str]:
        self._update_job(
            validation_job_id,
            status="DEPLOYING_ENVIRONMENT",
            current_stage="deploy",
            progress=20,
            updated_at=now_iso(),
        )
        result = {
            "validation_run_id": f"run-{validation_job_id}",
            "namespace": f"elden-staging-{validation_job_id}",
            "candidate_endpoint": f"http://candidate.{validation_job_id}.svc.cluster.local",
            "stable_endpoint": f"http://stable.{validation_job_id}.svc.cluster.local",
            "candidate_image": candidate_image,
        }
        write_json(self.artifact_dir / "deploy" / f"{validation_job_id}.json", result)
        return result

    def cleanup(self, validation_job_id: str, namespace: str | None = None) -> dict[str, Any]:
        result = {
            "validation_job_id": validation_job_id,
            "namespace": namespace or f"elden-staging-{validation_job_id}",
            "cleanup_status": "completed",
        }
        write_json(self.artifact_dir / "cleanup" / f"{validation_job_id}.json", result)
        return result

    def startup_check(self, validation_job_id: str, request: dict[str, Any]) -> ValidationStageResult:
        self._update_job(
            validation_job_id,
            status="STARTUP_CHECKING",
            current_stage="startup_check",
            progress=35,
            updated_at=now_iso(),
        )
        result = self._llm_stage_result(
            validation_job_id,
            "startup",
            request,
            extra={
                "startup_timeout_seconds": self.settings.startup_timeout_seconds,
                "expected_decision": "fail if candidate_image is empty or startup evidence indicates boot/readiness failure",
            },
        )
        return self._save_stage(validation_job_id, "startup", result)

    def regression_test(self, validation_job_id: str, request: dict[str, Any]) -> ValidationStageResult:
        self._update_job(
            validation_job_id,
            status="REGRESSION_TESTING",
            current_stage="regression_test",
            progress=55,
            updated_at=now_iso(),
        )
        result = self._llm_stage_result(
            validation_job_id,
            "regression",
            request,
            extra={
                "expected_decision": "fail if patch evidence suggests unrelated behavior changes or regression evidence is negative",
            },
        )
        return self._save_stage(validation_job_id, "regression", result)

    def security_replay(
        self,
        validation_job_id: str,
        request: dict[str, Any],
        runtime_context: dict[str, Any] | None,
    ) -> ValidationStageResult:
        self._update_job(
            validation_job_id,
            status="SECURITY_REPLAYING",
            current_stage="security_replay",
            progress=75,
            updated_at=now_iso(),
        )
        result = self._llm_stage_result(
            validation_job_id,
            "security_replay",
            request,
            runtime_context=runtime_context,
            extra={
                "expected_decision": (
                    "pass only if the patch diff plausibly neutralizes the original CWE and payload; "
                    "fail if vulnerable string interpolation, unescaped rendering, or path traversal remains"
                ),
            },
        )
        return self._save_stage(validation_job_id, "security_replay", result)

    def slo_check(self, validation_job_id: str, request: dict[str, Any]) -> ValidationStageResult:
        self._update_job(
            validation_job_id,
            status="SLO_CHECKING",
            current_stage="slo_check",
            progress=90,
            updated_at=now_iso(),
        )
        result = self._llm_stage_result(
            validation_job_id,
            "slo",
            request,
            extra={
                "max_p95_latency_increase_pct": self.settings.max_p95_latency_increase_pct,
                "max_error_rate_increase_pp": self.settings.max_error_rate_increase_pp,
                "max_throughput_drop_pct": self.settings.max_throughput_drop_pct,
                "expected_decision": "fail if patch or build evidence indicates material latency, error-rate, or throughput regression",
            },
        )
        return self._save_stage(validation_job_id, "slo", result)

    def _llm_stage_result(
        self,
        validation_job_id: str,
        stage_name: str,
        request: dict[str, Any],
        *,
        runtime_context: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> ValidationStageResult:
        prompt = self._build_stage_prompt(stage_name, request, runtime_context, extra or {})
        prompt_path = self.artifact_dir / "llm" / "prompts" / f"{validation_job_id}-{stage_name}.txt"
        write_json(
            self.artifact_dir / "llm" / "inputs" / f"{validation_job_id}-{stage_name}.json",
            {
                "stage": stage_name,
                "request": request,
                "runtime_context": runtime_context,
                "extra": extra or {},
            },
        )
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")
        response = self.validation_client.generate_validation_json(
            prompt=prompt,
            workdir=self.settings.artifact_dir,
            schema=self._llm_stage_schema(),
        )
        response_path = self.artifact_dir / "llm" / "responses" / f"{validation_job_id}-{stage_name}.json"
        response_path.parent.mkdir(parents=True, exist_ok=True)
        response_path.write_text(response.raw_text, encoding="utf-8")

        status = response.payload.get("status")
        if status not in {"pass", "fail"}:
            raise ValueError(f"LLM validation output for {stage_name} must contain status=pass|fail")
        summary = response.payload.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError(f"LLM validation output for {stage_name} must contain a non-empty summary")
        metrics = response.payload.get("metrics") or {}
        if not isinstance(metrics, dict):
            raise ValueError(f"LLM validation output for {stage_name} must contain metrics object")
        metrics = {
            **metrics,
            "llm_provider": response.provider,
            "llm_model": response.model,
            "llm_based": True,
        }
        return ValidationStageResult(status=status, summary=summary, metrics=metrics)

    def _llm_stage_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["pass", "fail"]},
                "summary": {"type": "string"},
                "metrics": {
                    "type": "object",
                    "additionalProperties": True,
                },
            },
            "required": ["status", "summary", "metrics"],
            "additionalProperties": False,
        }

    def _build_stage_prompt(
        self,
        stage_name: str,
        request: dict[str, Any],
        runtime_context: dict[str, Any] | None,
        extra: dict[str, Any],
    ) -> str:
        patch_diff = self._read_patch_file(request.get("patch_file"))
        evidence = {
            "stage": stage_name,
            "candidate": request,
            "runtime_context": runtime_context,
            "patch_diff": patch_diff[:12000],
            "stage_rules": extra,
        }
        return "\n".join(
            [
                "You are the ELDEN RING Phase 3 Recovery Assurance validator.",
                "Evaluate only the requested validation stage using the supplied candidate payload, runtime attack context, and patch diff.",
                "Return only JSON matching this schema: {\"status\":\"pass|fail\",\"summary\":\"...\",\"metrics\":{...}}.",
                "Do not include markdown fences or prose outside the JSON.",
                "Be conservative: if evidence is missing or the patch does not convincingly address the requested stage, return fail.",
                "Stage-specific guidance:",
                "- startup: assess whether the candidate can boot and satisfy readiness/liveness based on build and image evidence.",
                "- regression: assess whether the patch is minimal and unlikely to break existing behavior.",
                "- security_replay: assess whether the original CWE payload is neutralized by the diff.",
                "- slo: assess whether the patch is likely to stay within latency, error-rate, and throughput thresholds.",
                "Evidence JSON:",
                json.dumps(evidence, ensure_ascii=False, indent=2),
            ]
        )

    def _save_stage(self, validation_job_id: str, stage_name: str, result: ValidationStageResult) -> ValidationStageResult:
        path = self.artifact_dir / stage_name / f"{validation_job_id}.json"
        result.report_path = str(path)
        data = dump_json(result)
        write_json(path, data)
        configmap_name = {
            "startup": "ra-startup-results",
            "regression": "ra-regression-results",
            "security_replay": "ra-exploit-results",
            "slo": "ra-slo-results",
        }.get(stage_name)
        if configmap_name:
            write_json(
                self.artifact_dir / "configmap-results" / f"{configmap_name}.json",
                {
                    "metadata": {"name": configmap_name, "namespace": "elden-staging"},
                    "data": {
                        "status": "PASSED" if result.status == "pass" else "FAILED",
                        "details": result.summary,
                    },
                },
            )
        self.store.save_stage(validation_job_id, stage_name, data)
        return result

    def _update_job(self, validation_job_id: str, **updates: Any) -> None:
        if self.store.get_job(validation_job_id):
            self.store.update_job(validation_job_id, **updates)

    def _read_patch_file(self, patch_file: str | None) -> str:
        if not patch_file:
            return ""
        path = Path(patch_file)
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
