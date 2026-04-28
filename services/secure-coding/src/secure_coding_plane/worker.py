from __future__ import annotations

import json
import time
from typing import Any

from .config import PlaneSettings, load_settings
from .messaging import Redis
from .schemas import RuntimeContextPackage, SecureCodingRetryRequest
from .service import SecureCodingService
from .storage import PlaneStore


class SecureCodingWorker:
    def __init__(self, settings: PlaneSettings | None = None) -> None:
        self.settings = settings or load_settings()
        self.store = PlaneStore(self.settings.db_path)
        self.service = SecureCodingService.from_settings(self.settings, self.store)
        self._client = None
        if self.settings.redis_url and Redis is not None:
            self._client = Redis.from_url(self.settings.redis_url, decode_responses=True)

    def close(self) -> None:
        self.store.close()

    def handle_ingest_payload(self, payload: dict[str, Any]) -> str:
        request = RuntimeContextPackage.model_validate(payload)
        accepted = self.service.submit_context_sync(request)
        return accepted.job_id

    def handle_retry_payload(self, payload: dict[str, Any]) -> str:
        job_id = self._resolve_retry_job_id(payload)
        request = SecureCodingRetryRequest.model_validate(
            {
                "reason": payload.get("reason") or "phase3_validation_failed",
                "retry_from_step": payload.get("retry_from_step") or "patch",
                "validation_feedback": self._build_validation_feedback(payload),
            }
        )
        self.service.retry_job_sync(job_id, request)
        return job_id

    def _resolve_retry_job_id(self, payload: dict[str, Any]) -> str:
        job_id = payload.get("job_id")
        if isinstance(job_id, str) and job_id:
            return job_id

        phase2 = payload.get("phase2")
        if isinstance(phase2, dict):
            phase2_job_id = phase2.get("job_id")
            if isinstance(phase2_job_id, str) and phase2_job_id:
                return phase2_job_id

        event_id = None
        if isinstance(phase2, dict):
            event_id = phase2.get("event_id")
        if not event_id:
            event_id = payload.get("event_id") or payload.get("incident_id")
        if isinstance(event_id, str) and event_id:
            job = self.store.get_secure_job_by_event(event_id)
            if job:
                return job["job_id"]

        raise KeyError("Retry payload must include job_id or a resolvable event_id/incident_id")

    def _build_validation_feedback(self, payload: dict[str, Any]) -> dict[str, Any]:
        feedback = payload.get("validation_feedback")
        merged = dict(feedback) if isinstance(feedback, dict) else {}
        for key in ("exploit", "regression", "slo", "severity"):
            value = payload.get(key)
            if value is not None:
                merged[key] = value
        phase2 = payload.get("phase2")
        if isinstance(phase2, dict):
            merged["phase2"] = phase2
        return merged

    def run_forever(self, sleep_sec: float = 1.0) -> None:
        if self._client is None:
            raise RuntimeError("Redis worker requires PLANE_REDIS_URL and redis package")
        pubsub = self._client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(self.settings.secure_coding_ingest_channel, self.settings.secure_coding_retry_channel)
        try:
            while True:
                message = pubsub.get_message(timeout=sleep_sec)
                if not message:
                    time.sleep(sleep_sec)
                    continue
                channel = message["channel"]
                payload = json.loads(message["data"])
                if channel == self.settings.secure_coding_ingest_channel:
                    self.handle_ingest_payload(payload)
                elif channel == self.settings.secure_coding_retry_channel:
                    self.handle_retry_payload(payload)
        finally:
            pubsub.close()
