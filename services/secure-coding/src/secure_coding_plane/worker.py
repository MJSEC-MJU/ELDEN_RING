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
        job_id = payload["job_id"]
        request = SecureCodingRetryRequest.model_validate(
            {
                "reason": payload["reason"],
                "retry_from_step": payload["retry_from_step"],
                "validation_feedback": payload.get("validation_feedback", {}),
            }
        )
        self.service.retry_job_sync(job_id, request)
        return job_id

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
