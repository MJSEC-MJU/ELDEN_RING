"""Redis dual-delivery client for Phase 2 context packages.

Delivers via both Pub/Sub (real-time) and List queue (persistent).
"""

import json
import logging
from typing import Optional

import redis

logger = logging.getLogger(__name__)


class RedisPublisher:
    def __init__(self, host: str = "redis-master.elden-monitoring", port: int = 6379):
        self.client: Optional[redis.Redis] = None
        self.host = host
        self.port = port
        self.channel = "elden:phase2:context"
        self.queue_key = "elden:phase2:context:queue"
        self._memory_backup: list[dict] = []
        self._connect()

    def _connect(self):
        try:
            self.client = redis.Redis(
                host=self.host, port=self.port, decode_responses=True
            )
            self.client.ping()
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
        except redis.ConnectionError:
            logger.warning(f"Cannot connect to Redis at {self.host}:{self.port}")
            self.client = None

    def publish_context(self, context: dict) -> bool:
        """Dual delivery: LPUSH to queue + PUBLISH to channel."""
        payload = json.dumps(context, ensure_ascii=False)
        try:
            if self.client is None:
                self._connect()
            if self.client is None:
                raise redis.ConnectionError("No connection")

            self.client.lpush(self.queue_key, payload)
            self.client.publish(self.channel, payload)
            logger.info(f"Context {context['context_id']} delivered (queue + pubsub)")
            return True
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            self._backup_to_memory(context)
            return False

    def _backup_to_memory(self, context: dict):
        self._memory_backup.append(context)
        logger.warning(
            f"Context {context['context_id']} backed up to memory "
            f"({len(self._memory_backup)} pending)"
        )

    def retry_memory_backup(self) -> int:
        """Retry sending memory-backed contexts. Returns number of successfully sent."""
        sent = 0
        remaining = []
        for ctx in self._memory_backup:
            if self.publish_context(ctx):
                sent += 1
            else:
                remaining.append(ctx)
                break  # stop on first failure
        # keep the ones that weren't attempted or failed
        idx = sent + len(remaining)
        self._memory_backup = self._memory_backup[sent:]
        return sent

    @property
    def pending_backup_count(self) -> int:
        return len(self._memory_backup)
