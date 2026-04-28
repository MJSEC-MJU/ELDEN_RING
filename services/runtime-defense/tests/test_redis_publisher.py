"""Tests for Redis dual-delivery publisher using fakeredis."""

import collections
import json

import fakeredis
import pytest

from src.redis_publisher import MAX_BACKUP_SIZE, RedisPublisher


def _new_pub() -> RedisPublisher:
    """Build a publisher without connecting (test-only)."""
    pub = RedisPublisher.__new__(RedisPublisher)
    pub.host = "localhost"
    pub.port = 6379
    pub.channel = "elden:phase2:context"
    pub.queue_key = "elden:phase2:context:queue"
    pub._memory_backup = collections.deque(maxlen=MAX_BACKUP_SIZE)
    pub._dropped_count = 0
    pub.client = fakeredis.FakeRedis(decode_responses=True)
    return pub


class TestRedisPublisher:
    def setup_method(self):
        self.pub = _new_pub()

    def test_publish_pushes_to_queue(self):
        ctx = {"context_id": "ctx-test-001", "data": "test"}
        result = self.pub.publish_context(ctx)
        assert result is True

        queued = self.pub.client.rpop(self.pub.queue_key)
        assert queued is not None
        assert json.loads(queued)["context_id"] == "ctx-test-001"

    def test_publish_multiple_contexts(self):
        for i in range(3):
            self.pub.publish_context({"context_id": f"ctx-{i}", "data": f"test-{i}"})

        length = self.pub.client.llen(self.pub.queue_key)
        assert length == 3

    def test_memory_backup_on_connection_failure(self, monkeypatch):
        self.pub.client = None
        monkeypatch.setattr(self.pub, "_connect", lambda: False)

        ctx = {"context_id": "ctx-backup-001", "data": "test"}
        result = self.pub.publish_context(ctx)
        assert result is False
        assert self.pub.pending_backup_count == 1


class TestDrainMemoryBackup:
    def setup_method(self):
        self.pub = _new_pub()

    def _stash(self, n: int) -> None:
        for i in range(n):
            self.pub._memory_backup.append({"context_id": f"ctx-{i}"})

    def test_drain_empty_returns_zero(self):
        assert self.pub.drain_memory_backup() == 0

    def test_drain_flushes_all_when_redis_up(self):
        self._stash(5)
        sent = self.pub.drain_memory_backup()
        assert sent == 5
        assert self.pub.pending_backup_count == 0
        assert self.pub.client.llen(self.pub.queue_key) == 5

    def test_drain_preserves_fifo_order(self):
        self._stash(3)
        self.pub.drain_memory_backup()
        # rpop pulls oldest (FIFO from the queue's tail)
        first = json.loads(self.pub.client.rpop(self.pub.queue_key))
        second = json.loads(self.pub.client.rpop(self.pub.queue_key))
        assert first["context_id"] == "ctx-0"
        assert second["context_id"] == "ctx-1"

    def test_drain_noop_when_redis_down(self, monkeypatch):
        self._stash(3)
        self.pub.client = None
        monkeypatch.setattr(self.pub, "_connect", lambda: False)
        sent = self.pub.drain_memory_backup()
        assert sent == 0
        assert self.pub.pending_backup_count == 3  # nothing lost


class TestBackupCapacity:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        self.pub = _new_pub()
        # Tiny cap to exercise overflow without bulk-loading 1000 items.
        self.pub._memory_backup = collections.deque(maxlen=3)
        self.pub.client = None
        monkeypatch.setattr(self.pub, "_connect", lambda: False)

    def test_overflow_drops_oldest(self):
        for i in range(5):
            self.pub.publish_context({"context_id": f"ctx-{i}"})

        assert self.pub.pending_backup_count == 3
        # Oldest two (ctx-0, ctx-1) should have been dropped; ctx-2..4 retained.
        retained = [c["context_id"] for c in self.pub._memory_backup]
        assert retained == ["ctx-2", "ctx-3", "ctx-4"]

    def test_dropped_counter_increments(self):
        for i in range(5):
            self.pub.publish_context({"context_id": f"ctx-{i}"})
        # 5 attempts, cap=3 → 2 drops
        assert self.pub.dropped_count == 2


class TestConnectionProbe:
    def test_is_connected_true_when_client_responsive(self):
        pub = _new_pub()
        assert pub.is_connected() is True

    def test_is_connected_false_when_client_none(self):
        pub = _new_pub()
        pub.client = None
        assert pub.is_connected() is False
