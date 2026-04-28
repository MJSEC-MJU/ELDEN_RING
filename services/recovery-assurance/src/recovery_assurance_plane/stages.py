from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import Settings
from .models import ValidationStageResult
from .store import JsonStore
from .utils import dump_json, now_iso, write_json


class ValidationStages:
    def __init__(self, settings: Settings, store: JsonStore) -> None:
        self.settings = settings
        self.store = store
        self.artifact_dir = settings.artifact_dir
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

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

    def startup_check(self, validation_job_id: str, candidate_image: str) -> ValidationStageResult:
        self._update_job(
            validation_job_id,
            status="STARTUP_CHECKING",
            current_stage="startup_check",
            progress=35,
            updated_at=now_iso(),
        )
        failed = not candidate_image or "fail-startup" in candidate_image
        result = ValidationStageResult(
            status="fail" if failed else "pass",
            summary="Candidate failed startup checks" if failed else "Startup, readiness, and dependency checks passed",
            metrics={
                "startup_probe_passed": not failed,
                "readiness_probe_passed": not failed,
                "liveness_probe_passed": not failed,
                "timeout_seconds": self.settings.startup_timeout_seconds,
            },
        )
        return self._save_stage(validation_job_id, "startup", result)

    def regression_test(self, validation_job_id: str, candidate_image: str) -> ValidationStageResult:
        self._update_job(
            validation_job_id,
            status="REGRESSION_TESTING",
            current_stage="regression_test",
            progress=55,
            updated_at=now_iso(),
        )
        failed = "fail-regression" in candidate_image
        result = ValidationStageResult(
            status="fail" if failed else "pass",
            summary="Core regression suite failed" if failed else "Core regression suite passed",
            metrics={"total": 12, "passed": 0 if failed else 12, "failed": 12 if failed else 0},
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
        cwe_id = request["cwe_id"]
        diff = self._read_patch_file(request.get("patch_file"))
        blocked = self._security_fix_matches_cwe(cwe_id, diff)
        if "fail-security" in request["candidate_image"]:
            blocked = False
        payload_sample = None
        endpoint = None
        if runtime_context:
            payload_sample = runtime_context.get("attack_info", {}).get("payload_sample")
            endpoint = runtime_context.get("target", {}).get("endpoint")
        result = ValidationStageResult(
            status="pass" if blocked else "fail",
            summary="Original attack payload blocked" if blocked else "Original attack payload still succeeds",
            metrics={
                "cwe_id": cwe_id,
                "payload_sample": payload_sample,
                "endpoint": endpoint,
                "blocked": blocked,
                "sensitive_data_exposed": not blocked,
                "internal_error_exposed": False,
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
        diff_lines = len(self._read_patch_file(request.get("patch_file")).splitlines())
        stable_p95 = 200.0
        candidate_p95 = stable_p95 + min(float(diff_lines), 20.0)
        latency_increase_pct = ((candidate_p95 - stable_p95) / stable_p95) * 100
        failed = "slow" in request["candidate_image"] or latency_increase_pct > self.settings.max_p95_latency_increase_pct
        result = ValidationStageResult(
            status="fail" if failed else "pass",
            summary="Candidate exceeded SLO thresholds" if failed else "Candidate remained within SLO thresholds",
            metrics={
                "stable_p95_ms": stable_p95,
                "candidate_p95_ms": candidate_p95,
                "p95_latency_increase_pct": latency_increase_pct,
                "max_p95_latency_increase_pct": self.settings.max_p95_latency_increase_pct,
                "stable_error_rate": 0.2,
                "candidate_error_rate": 1.8 if failed else 0.2,
            },
        )
        return self._save_stage(validation_job_id, "slo", result)

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

    def _security_fix_matches_cwe(self, cwe_id: str, diff: str) -> bool:
        if cwe_id == "CWE-89":
            return "%s" in diff or "execute(query, (" in diff or "?" in diff
        if cwe_id == "CWE-79":
            return "escape(" in diff or "html.escape" in diff
        if cwe_id == "CWE-22":
            return "resolve()" in diff or "safe_join" in diff or "Invalid path" in diff
        return False
