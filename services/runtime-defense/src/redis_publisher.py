"""Redis dual-delivery client for Phase 2 context packages.

Delivers each context via both a List queue (LPUSH, persistent) and a
Pub/Sub channel (PUBLISH, real-time). On Redis outage, contexts are
buffered to a bounded in-memory deque and drained back to Redis once
the connection recovers.

The drain loop runs as a background asyncio task started in
``main.py``'s lifespan handler.
"""

import collections
import json
import logging
from typing import Optional

import redis

from src import metrics
from src.config import settings

logger = logging.getLogger(__name__)


# When the in-memory backup is full we drop the OLDEST entry. Recent
# attack contexts are higher value for analysis than ones that have
# already aged out during a multi-minute Redis outage.
MAX_BACKUP_SIZE = settings.MEMORY_BACKUP_MAX_SIZE


class RedisPublisher:
    def __init__(self, host: str = "redis-master.elden-monitoring", port: int = 6379):
        self.client: Optional[redis.Redis] = None
        self.host = host
        self.port = port
        self.channel = settings.REDIS_PUBSUB_CHANNEL
        self.queue_key = settings.REDIS_QUEUE_KEY
        self._memory_backup: collections.deque[dict] = collections.deque(
            maxlen=MAX_BACKUP_SIZE
        )
        self._dropped_count = 0
        self._connect()

    def _connect(self) -> bool:
        try:
            self.client = redis.Redis(
                host=self.host,
                port=self.port,
                decode_responses=True,
                socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT,
                socket_timeout=settings.REDIS_OP_TIMEOUT,
            )
            self.client.ping()
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
            return True
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Cannot connect to Redis at {self.host}:{self.port}: {e}")
            self.client = None
            return False

    def _try_publish(self, context: dict) -> bool:
        """Single attempt: lazy reconnect, LPUSH + PUBLISH, no backup logic."""
        if self.client is None and not self._connect():
            return False

        try:
            payload = json.dumps(context, ensure_ascii=False)
            self.client.lpush(self.queue_key, payload)
            self.client.publish(self.channel, payload)
            return True
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis publish failed: {e}")
            self.client = None
            return False

    def publish_context(self, context: dict) -> bool:
        """Publish or buffer to memory. Memory drain runs in background."""
        if self._try_publish(context):
            logger.info(f"Context {context['context_id']} delivered (queue + pubsub)")
            return True
        self._backup_to_memory(context)
        return False

    def _backup_to_memory(self, context: dict) -> None:
        """Append to bounded deque. Oldest entry drops when at capacity."""
        cap = self._memory_backup.maxlen or MAX_BACKUP_SIZE
        was_full = len(self._memory_backup) == cap
        self._memory_backup.append(context)
        metrics.redis_backup_pending.set(len(self._memory_backup))
        if was_full:
            self._dropped_count += 1
            metrics.redis_backup_dropped_total.inc()
            logger.warning(
                f"Memory backup full ({cap}) — dropped oldest "
                f"(total dropped: {self._dropped_count})"
            )
        else:
            logger.warning(
                f"Context {context['context_id']} backed up to memory "
                f"({len(self._memory_backup)}/{cap})"
            )

    def drain_memory_backup(self) -> int:
        """Flush as many backed-up contexts to Redis as possible.

        Returns the number successfully sent. Stops on first failure so
        the next drain attempt picks up where this one left off (FIFO).
        """
        if not self._memory_backup:
            return 0

        if self.client is None and not self._connect():
            return 0

        sent = 0
        while self._memory_backup:
            ctx = self._memory_backup[0]
            if not self._try_publish(ctx):
                break
            self._memory_backup.popleft()
            sent += 1

        if sent:
            metrics.redis_backup_pending.set(len(self._memory_backup))
            logger.info(
                f"Drained {sent} contexts from memory backup "
                f"({len(self._memory_backup)} remaining)"
            )
        return sent

    def is_connected(self) -> bool:
        """Probe connection. Refreshes self.client on failure."""
        if self.client is None:
            return False
        try:
            self.client.ping()
            return True
        except (redis.ConnectionError, redis.TimeoutError):
            self.client = None
            return False

    @property
    def pending_backup_count(self) -> int:
        return len(self._memory_backup)

    @property
    def dropped_count(self) -> int:
        return self._dropped_count
