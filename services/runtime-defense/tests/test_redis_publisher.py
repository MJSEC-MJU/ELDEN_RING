"""Tests for Redis dual-delivery publisher using fakeredis."""

import json
import pytest
import fakeredis

from src.redis_publisher import RedisPublisher


class TestRedisPublisher:
    def setup_method(self):
        self.pub = RedisPublisher.__new__(RedisPublisher)
        self.pub.client = fakeredis.FakeRedis(decode_responses=True)
        self.pub.host = "localhost"
        self.pub.port = 6379
        self.pub.channel = "elden:phase2:context"
        self.pub.queue_key = "elden:phase2:context:queue"
        self.pub._memory_backup = []

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

    def test_memory_backup_on_connection_failure(self):
        self.pub.client = None  # simulate connection loss
        ctx = {"context_id": "ctx-backup-001", "data": "test"}
        result = self.pub.publish_context(ctx)
        assert result is False
        assert self.pub.pending_backup_count == 1
