from __future__ import annotations

import json
from typing import Any

from .config import PlaneSettings
from .storage import PlaneStore

try:
    from redis import Redis
except Exception:  # pragma: no cover
    Redis = None


class MessageBus:
    def __init__(self, settings: PlaneSettings, store: PlaneStore) -> None:
        self.settings = settings
        self.store = store
        self._client = None
        if settings.redis_url and Redis is not None:
            self._client = Redis.from_url(settings.redis_url, decode_responses=True)

    def publish(self, channel: str, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False)
        self.store.save_message(channel=channel, direction="outbound", payload=payload)
        if self._client is None:
            return
        try:
            self._client.publish(channel, body)
        except Exception as exc:  # pragma: no cover
            self.store.save_message(
                channel=f"{channel}:publish-error",
                direction="error",
                payload={"error": str(exc), "payload": payload},
            )
