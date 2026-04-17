from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.secure_coding_plane.config import PlaneSettings
from src.secure_coding_plane.worker import SecureCodingWorker


class SecureCodingWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        workspace = root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "routes").mkdir(parents=True, exist_ok=True)
        (workspace / "routes" / "auth.py").write_text(
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
            workspace_root=workspace,
            artifact_root=root / "artifacts",
            db_path=root / "secure_coding.db",
            redis_url=None,
            secure_coding_llm_provider="mock",
        )
        self.worker = SecureCodingWorker(self.settings)

    def tearDown(self) -> None:
        self.worker.close()
        self.temp_dir.cleanup()

    def test_handle_ingest_payload_processes_job(self) -> None:
        job_id = self.worker.handle_ingest_payload(
            {
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
        )

        job = self.worker.store.get_secure_job(job_id)
        self.assertIsNotNone(job)
        self.assertEqual("COMPLETED", job["status"])
        patched_source = (self.settings.workspace_root / "routes" / "auth.py").read_text(encoding="utf-8")
        self.assertIn("db.execute(query, (username, password))", patched_source)


if __name__ == "__main__":
    unittest.main()
