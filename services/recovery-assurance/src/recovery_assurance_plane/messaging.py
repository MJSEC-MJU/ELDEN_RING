from __future__ import annotations

import json
from typing import Any

from .config import Settings
from .store import JsonStore


class MessageBus:
    def __init__(self, settings: Settings, store: JsonStore) -> None:
        self.settings = settings
        self.store = store
        self._redis = None
        if settings.redis_url:
            try:
                import redis

                self._redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
            except Exception:
                self._redis = None

    def publish(self, channel: str, payload: dict[str, Any]) -> None:
        self.store.save_message(channel, payload)
        if self._redis is not None:
            self._redis.publish(channel, json.dumps(payload, ensure_ascii=False))

    def consume_once(self, timeout: int = 1) -> dict[str, Any] | None:
        if self._redis is None:
            return None
        pubsub = self._redis.pubsub()
        pubsub.subscribe(self.settings.validate_channel)
        message = pubsub.get_message(timeout=timeout)
        if message and message.get("type") == "message":
            return json.loads(message["data"])
        return None

