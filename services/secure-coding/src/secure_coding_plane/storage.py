from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .utils import utcnow_iso


class PlaneStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS runtime_contexts (
                context_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS secure_coding_jobs (
                job_id TEXT PRIMARY KEY,
                context_id TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                cwe_id TEXT NOT NULL,
                status TEXT NOT NULL,
                current_step TEXT NOT NULL,
                progress INTEGER NOT NULL,
                error_code TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS secure_analysis (
                job_id TEXT PRIMARY KEY,
                scope_json TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS secure_strategy (
                job_id TEXT PRIMARY KEY,
                strategy_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS secure_patches (
                patch_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                target_file TEXT NOT NULL,
                target_function TEXT NOT NULL,
                patch_file TEXT NOT NULL,
                unified_diff TEXT NOT NULL,
                patch_status TEXT NOT NULL,
                change_summary_json TEXT NOT NULL,
                patched_file_path TEXT,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS secure_builds (
                build_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                patch_id TEXT NOT NULL,
                candidate_image TEXT NOT NULL,
                build_log TEXT NOT NULL,
                build_status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS secure_retry_requests (
                retry_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                retry_from_step TEXT NOT NULL,
                reason TEXT NOT NULL,
                validation_feedback_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                direction TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
        ]
        with self._lock:
            for statement in statements:
                self._conn.execute(statement)
            self._conn.commit()

    def _execute(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            cursor = self._conn.execute(query, params)
            self._conn.commit()
            return cursor

    def _fetchone(self, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            cursor = self._conn.execute(query, params)
            row = cursor.fetchone()
        return dict(row) if row else None

    def _dumps(self, payload: Any) -> str:
        return json.dumps(payload, ensure_ascii=False, default=str)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def save_runtime_context(self, payload: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO runtime_contexts (context_id, event_id, payload_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (payload["context_id"], payload["event_id"], self._dumps(payload), utcnow_iso()),
        )

    def get_runtime_context(self, context_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT payload_json FROM runtime_contexts WHERE context_id = ?", (context_id,))
        return json.loads(row["payload_json"]) if row else None

    def get_secure_job_by_event(self, event_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM secure_coding_jobs WHERE event_id = ?", (event_id,))

    def create_secure_job(
        self,
        *,
        job_id: str,
        context_id: str,
        event_id: str,
        cwe_id: str,
        status: str,
        current_step: str,
        progress: int,
    ) -> None:
        now = utcnow_iso()
        self._execute(
            """
            INSERT INTO secure_coding_jobs (
                job_id, context_id, event_id, cwe_id, status, current_step, progress, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, context_id, event_id, cwe_id, status, current_step, progress, now, now),
        )

    def update_secure_job(
        self,
        job_id: str,
        *,
        status: str,
        current_step: str,
        progress: int,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        self._execute(
            """
            UPDATE secure_coding_jobs
            SET status = ?, current_step = ?, progress = ?, error_code = ?, error_message = ?, updated_at = ?
            WHERE job_id = ?
            """,
            (status, current_step, progress, error_code, error_message, utcnow_iso(), job_id),
        )

    def get_secure_job(self, job_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM secure_coding_jobs WHERE job_id = ?", (job_id,))

    def save_secure_analysis(self, job_id: str, scope: dict[str, Any], findings: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO secure_analysis (job_id, scope_json, findings_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (job_id, self._dumps(scope), self._dumps(findings), utcnow_iso()),
        )

    def get_secure_analysis(self, job_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM secure_analysis WHERE job_id = ?", (job_id,))
        if not row:
            return None
        return {"scope": json.loads(row["scope_json"]), "findings": json.loads(row["findings_json"])}

    def save_secure_strategy(self, job_id: str, strategy: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO secure_strategy (job_id, strategy_json, created_at)
            VALUES (?, ?, ?)
            """,
            (job_id, self._dumps(strategy), utcnow_iso()),
        )

    def get_secure_strategy(self, job_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT strategy_json FROM secure_strategy WHERE job_id = ?", (job_id,))
        return json.loads(row["strategy_json"]) if row else None

    def save_secure_patch(
        self,
        *,
        patch_id: str,
        job_id: str,
        event_id: str,
        target_file: str,
        target_function: str,
        patch_file: str,
        unified_diff: str,
        patch_status: str,
        change_summary: dict[str, Any],
        patched_file_path: str | None,
    ) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO secure_patches (
                patch_id, job_id, event_id, target_file, target_function, patch_file,
                unified_diff, patch_status, change_summary_json, patched_file_path, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                patch_id,
                job_id,
                event_id,
                target_file,
                target_function,
                patch_file,
                unified_diff,
                patch_status,
                self._dumps(change_summary),
                patched_file_path,
                utcnow_iso(),
            ),
        )

    def get_secure_patch(self, patch_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM secure_patches WHERE patch_id = ?", (patch_id,))
        if not row:
            return None
        row["change_summary_json"] = json.loads(row["change_summary_json"])
        return row

    def get_secure_patch_by_job(self, job_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM secure_patches WHERE job_id = ?", (job_id,))
        if not row:
            return None
        row["change_summary_json"] = json.loads(row["change_summary_json"])
        return row

    def save_secure_build(
        self,
        *,
        build_id: str,
        job_id: str,
        patch_id: str,
        candidate_image: str,
        build_log: str,
        build_status: str,
    ) -> None:
        self._execute(
            """
            INSERT OR REPLACE INTO secure_builds (
                build_id, job_id, patch_id, candidate_image, build_log, build_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (build_id, job_id, patch_id, candidate_image, build_log, build_status, utcnow_iso()),
        )

    def get_secure_build_by_job(self, job_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM secure_builds WHERE job_id = ?", (job_id,))

    def save_secure_retry_request(
        self,
        *,
        retry_id: str,
        job_id: str,
        retry_from_step: str,
        reason: str,
        validation_feedback: dict[str, Any],
    ) -> None:
        self._execute(
            """
            INSERT INTO secure_retry_requests (
                retry_id, job_id, retry_from_step, reason, validation_feedback_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (retry_id, job_id, retry_from_step, reason, self._dumps(validation_feedback), utcnow_iso()),
        )

    def count_secure_retry_requests(self, job_id: str) -> int:
        row = self._fetchone("SELECT COUNT(*) AS retry_count FROM secure_retry_requests WHERE job_id = ?", (job_id,))
        return int(row["retry_count"]) if row else 0

    def save_message(self, *, channel: str, direction: str, payload: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO messages (channel, direction, payload_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (channel, direction, self._dumps(payload), utcnow_iso()),
        )

    def list_messages(self, channel: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM messages"
        params: tuple[Any, ...] = ()
        if channel:
            query += " WHERE channel = ?"
            params = (channel,)
        query += " ORDER BY id"
        with self._lock:
            cursor = self._conn.execute(query, params)
            rows = cursor.fetchall()
        messages: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload_json"] = json.loads(item["payload_json"])
            messages.append(item)
        return messages
