from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from recovery_assurance_plane.app import create_app
from recovery_assurance_plane.config import Settings


def make_settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        artifact_dir=tmp_path / "artifacts",
        redis_url=None,
        validate_channel="elden:phase3:validate",
        retry_channel="elden:phase2:retry",
        promote_channel="elden:phase4:promote",
        stable_image="registry.local/target-app:stable",
        startup_timeout_seconds=120,
        max_p95_latency_increase_pct=15,
        max_error_rate_increase_pp=1,
        max_throughput_drop_pct=10,
    )


def make_payload(patch_file: Path, image: str = "registry.local/target-app:candidate") -> dict:
    return {
        "context_id": "ctx-001",
        "event_id": "evt-001",
        "patch_id": "patch-001",
        "job_id": "sc-job-001",
        "cwe_id": "CWE-89",
        "target_file": "routes/auth.py",
        "target_function": "login_handler",
        "patch_file": str(patch_file),
        "candidate_image": image,
        "severity": "HIGH",
        "build_log": "artifacts/builds/build-001.log",
        "analysis_summary": {
            "root_cause": "raw SQL query",
            "fix_strategy": "parameterized query",
        },
        "patch_status": "READY_FOR_VALIDATION",
    }


def test_successful_validation_reaches_governance(tmp_path: Path) -> None:
    patch_file = tmp_path / "patch.diff"
    patch_file.write_text("+ cursor.execute(query, (username,))\n", encoding="utf-8")
    app = create_app(make_settings(tmp_path))
    client = TestClient(app)

    accepted = client.post("/api/v1/recovery-assurance/validate", json=make_payload(patch_file))
    assert accepted.status_code == 202
    validation_job_id = accepted.json()["validation_job_id"]

    result = client.get(f"/api/v1/recovery-assurance/jobs/{validation_job_id}/result")
    assert result.status_code == 200
    body = result.json()
    assert body["status"] == "COMPLETED"
    assert body["result"]["status"] == "ready_for_governance"
    assert body["result"]["validation_result"]["security_replay"]["status"] == "pass"

    store = json.loads((tmp_path / "data" / "phase3-store.json").read_text(encoding="utf-8"))
    promote = store["messages"][-1]["payload"]
    assert store["messages"][-1]["channel"] == "elden:phase4:promote"
    assert promote["phase2"]["job_id"] == "sc-job-001"
    assert promote["phase2"]["patch_id"] == "patch-001"
    assert promote["severity"] == "HIGH"
    assert promote["exploit"] == "PASSED"
    assert promote["regression"] == "PASSED"
    assert promote["slo"] == "PASSED"


def test_security_replay_failure_requests_retry(tmp_path: Path) -> None:
    patch_file = tmp_path / "patch.diff"
    patch_file.write_text("+ unsafe string query still here\n", encoding="utf-8")
    app = create_app(make_settings(tmp_path))
    client = TestClient(app)

    accepted = client.post("/api/v1/recovery-assurance/validate", json=make_payload(patch_file))
    assert accepted.status_code == 202
    validation_job_id = accepted.json()["validation_job_id"]

    result = client.get(f"/api/v1/recovery-assurance/jobs/{validation_job_id}/result")
    assert result.status_code == 200
    body = result.json()
    assert body["status"] == "FAILED"
    assert body["result"]["next_action"] == "request_secure_coding_retry"
    assert body["result"]["validation_result"]["security_replay"]["status"] == "fail"
    assert body["result"]["validation_result"]["slo"]["status"] == "not_run"

    store = json.loads((tmp_path / "data" / "phase3-store.json").read_text(encoding="utf-8"))
    retry = store["messages"][-1]["payload"]
    assert store["messages"][-1]["channel"] == "elden:phase2:retry"
    assert retry["job_id"] == "sc-job-001"
    assert retry["phase2"]["event_id"] == "evt-001"
