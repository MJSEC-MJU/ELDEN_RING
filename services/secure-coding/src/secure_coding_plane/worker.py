from __future__ import annotations

import json
import logging
import math
import time
from typing import Any

from .config import PlaneSettings, load_settings
from .messaging import Redis
from .schemas import RuntimeContextPackage, SecureCodingRetryRequest
from .service import SecureCodingService
from .storage import PlaneStore


logger = logging.getLogger(__name__)


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
        if not request.metadata.requires_patch:
            logger.info("skipping context without patch requirement: event_id=%s", request.event_id)
            return f"skipped:{request.event_id}"
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

    @staticmethod
    def _as_text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)

    def _payload_from_redis(self, value: Any) -> dict[str, Any]:
        return json.loads(self._as_text(value))

    def _handle_queue_result(self, result: Any) -> str | None:
        if not result:
            return None
        _queue_name, data = result
        return self.handle_ingest_payload(self._payload_from_redis(data))

    def _handle_pubsub_message(self, message: dict[str, Any], *, allow_ingest: bool) -> str | None:
        channel = self._as_text(message["channel"])
        payload = self._payload_from_redis(message["data"])
        if channel == self.settings.secure_coding_retry_channel:
            return self.handle_retry_payload(payload)
        if allow_ingest and channel == self.settings.secure_coding_ingest_channel:
            return self.handle_ingest_payload(payload)
        return None

    def _record_worker_error(self, *, source: str, payload: Any, exc: Exception) -> None:
        logger.exception("secure-coding worker failed while processing %s", source)
        self.store.save_message(
            channel="secure-coding:worker:error",
            direction="error",
            payload={
                "source": source,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "payload_preview": self._payload_preview(payload),
            },
        )

    def _payload_preview(self, payload: Any, limit: int = 2000) -> str:
        try:
            if isinstance(payload, bytes):
                text = payload.decode("utf-8", errors="replace")
            elif isinstance(payload, str):
                text = payload
            else:
                text = json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            text = repr(payload)
        if len(text) > limit:
            return f"{text[:limit]}...<truncated>"
        return text

    def run_forever(self, sleep_sec: float = 1.0) -> None:
        if self._client is None:
            raise RuntimeError("Redis worker requires PLANE_REDIS_URL and redis package")
        pubsub = self._client.pubsub(ignore_subscribe_messages=True)
        ingest_queue = self.settings.secure_coding_ingest_queue
        use_ingest_pubsub_fallback = not ingest_queue
        channels = [self.settings.secure_coding_retry_channel]
        if use_ingest_pubsub_fallback:
            channels.append(self.settings.secure_coding_ingest_channel)
        pubsub.subscribe(*channels)
        queue_timeout = max(1, math.ceil(sleep_sec))
        try:
            while True:
                handled = False
                while True:
                    message = pubsub.get_message(timeout=0)
                    if not message:
                        break
                    source = self._as_text(message.get("channel", "unknown-pubsub"))
                    try:
                        self._handle_pubsub_message(message, allow_ingest=use_ingest_pubsub_fallback)
                    except Exception as exc:
                        self._record_worker_error(source=source, payload=message.get("data"), exc=exc)
                    handled = True

                if ingest_queue:
                    result = self._client.brpop(ingest_queue, timeout=queue_timeout)
                    if result:
                        _queue_name, data = result
                        try:
                            self._handle_queue_result(result)
                        except Exception as exc:
                            self._record_worker_error(source=ingest_queue, payload=data, exc=exc)
                        handled = True

                if not handled and not ingest_queue:
                    time.sleep(sleep_sec)
        finally:
            pubsub.close()
