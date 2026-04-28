from __future__ import annotations

import json
import time
from typing import Any

from .config import Settings, load_settings
from .constants import SUPPORTED_CWE
from .messaging import MessageBus
from .models import CandidateValidationRequest
from .service import RecoveryAssuranceService
from .store import JsonStore
from .utils import dump_json, generate_id, now_iso

try:
    from redis import Redis
except Exception:  # pragma: no cover
    Redis = None


class RecoveryAssuranceWorker:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        self.store = JsonStore(self.settings.data_dir)
        self.bus = MessageBus(self.settings, self.store)
        self.service = RecoveryAssuranceService(self.settings, self.store, self.bus)
        self._client = None
        if self.settings.redis_url and Redis is not None:
            self._client = Redis.from_url(self.settings.redis_url, decode_responses=True)

    def handle_validate_payload(self, payload: dict[str, Any]) -> str:
        request = CandidateValidationRequest.model_validate(payload)
        if request.patch_status != "READY_FOR_VALIDATION":
            raise ValueError("Patch is not ready for validation")
        if request.cwe_id not in SUPPORTED_CWE:
            raise ValueError("Unsupported CWE for current PoC")
        existing = self.store.get_job_by_patch(request.patch_id)
        if existing:
            return existing["validation_job_id"]

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
        self.service.process_validation(validation_job_id, dump_json(request))
        return validation_job_id

    def run_forever(self, sleep_sec: float = 1.0) -> None:
        if self._client is None:
            raise RuntimeError("Redis worker requires REDIS_URL and redis package")
        pubsub = self._client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(self.settings.validate_channel)
        try:
            while True:
                message = pubsub.get_message(timeout=sleep_sec)
                if not message:
                    time.sleep(sleep_sec)
                    continue
                self.handle_validate_payload(json.loads(message["data"]))
        finally:
            pubsub.close()
