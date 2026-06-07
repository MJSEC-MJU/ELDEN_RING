from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from src.secure_coding_plane.app import create_secure_coding_app
from src.secure_coding_plane.config import PlaneSettings
from src.secure_coding_plane.llm_clients import LlmStructuredResponse


class FakePatchClient:
    def generate_patch_json(self, *, prompt, workdir, schema):
        return LlmStructuredResponse(
            payload={
                "patched_snippet": "\n".join(
                    [
                        "def login_handler(username, password):",
                        "    query = \"SELECT * FROM users WHERE username = ? AND password = ?\"",
                        "    result = db.execute(query, (username, password))",
                        "    return result",
                    ]
                ),
                "change_summary": {"security_fix": "parameterized query binding"},
            },
            raw_text='{"patched_snippet":"...","change_summary":{"security_fix":"parameterized query binding"}}',
            provider="test_llm",
            model=None,
        )


class SecureCodingFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.workspace = root / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.workspace / "routes").mkdir(parents=True, exist_ok=True)
        (self.workspace / "routes" / "auth.py").write_text(
            "\n".join(
                [
                    "def login_handler(username, password):",
                    "    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
                    "    result = db.execute(query)",
                    "    return result",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        self.settings = PlaneSettings(
            workspace_root=self.workspace,
            artifact_root=root / "artifacts",
            db_path=root / "secure_coding.db",
            redis_url=None,
            secure_coding_llm_provider="codex",
        )
        self.client = TestClient(create_secure_coding_app(self.settings))
        self.client.app.state.service.patch_engine.patch_client = FakePatchClient()

    def tearDown(self) -> None:
        self.client.app.state.store.close()
        self.client.close()
        self.temp_dir.cleanup()

    def _context(self) -> dict:
        return {
            "context_id": "ctx-001",
            "event_id": "evt-001",
            "timestamp": "2026-04-15T10:00:00Z",
            "attack_info": {
                "category": "SQL Injection",
                "cwe_id": "CWE-89",
                "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
                "owasp_category": "A03:2021 Injection",
                "payload_sample": "username=admin' OR 1=1--&password=test",
                "source_ip": "127.0.0.1",
                "blocked": True,
            },
            "target": {
                "endpoint": {"method": "POST", "path": "/api/login"},
                "source_mapping": {
                    "file": "routes/auth.py",
                    "function": "login_handler",
                    "line_start": 1,
                    "line_end": 4,
                },
            },
            "metadata": {
                "severity": "HIGH",
                "pipeline_version": "1.0.0",
                "defense_action_taken": "blocked",
                "requires_patch": True,
            },
        }

    def test_end_to_end_llm_patch_flow(self) -> None:
        accepted = self.client.post("/api/v1/context", json=self._context())
        self.assertEqual(202, accepted.status_code, accepted.text)
        job_id = accepted.json()["job_id"]

        result_resp = self.client.get(f"/api/v1/secure-coding/jobs/{job_id}/result")
        self.assertEqual(200, result_resp.status_code, result_resp.text)
        result = result_resp.json()["result"]

        self.assertEqual("READY_FOR_VALIDATION", result["patch_status"])
        self.assertEqual(job_id, result["job_id"])
        self.assertEqual("HIGH", result["severity"])
        self.assertTrue(result["workspace_applied"])
        self.assertTrue(result["candidate_image"].startswith("ghcr.io/mjsec-mju/"))
        patched_source = (self.workspace / "routes" / "auth.py").read_text(encoding="utf-8")
        self.assertIn("db.execute(query, (username, password))", patched_source)
        messages = self.client.app.state.store.list_messages(self.settings.secure_coding_validate_channel)
        self.assertEqual(1, len(messages))
        payload = messages[0]["payload_json"]
        self.assertEqual(job_id, payload["job_id"])
        self.assertEqual("HIGH", payload["severity"])

    def test_internal_analyze_uses_runtime_defense_context_wording(self) -> None:
        response = self.client.post("/api/v1/secure-coding/internal/analyze", json=self._context())

        self.assertEqual(200, response.status_code, response.text)
        payload = response.json()
        self.assertEqual("runtime-defense-context", payload["vulnerability_context"]["source"])


if __name__ == "__main__":
    unittest.main()
