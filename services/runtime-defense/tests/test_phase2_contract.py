"""Phase 1 ↔ Phase 2 Redis contract tests.

Phase 1's RedisPublisher is the *producer* side of the inter-phase
message contract:

    LPUSH    elden:phase2:context:queue      ← primary path (BRPOP'd by P2)
    PUBLISH  elden:phase2:context            ← real-time fallback / observers

Phase 2's secure-coding worker (`services/secure-coding`) reads from
the queue via BRPOP. Any drift between the two keys means messages are
silently lost, so we enforce the contract here at the unit-test level.

The Phase 2 settings module is loaded via importlib by path so this
test does not require the secure-coding service to be installed as a
package next to runtime-defense.
"""

from __future__ import annotations

import collections
import importlib.util
import json
import os
import sys
from pathlib import Path

import fakeredis

from src.config import settings as phase1_settings
from src.redis_publisher import MAX_BACKUP_SIZE, RedisPublisher


REPO_ROOT = Path(__file__).resolve().parents[3]
P2_CONFIG_PATH = REPO_ROOT / "services" / "secure-coding" / "src" / "secure_coding_plane" / "config.py"


def _load_phase2_defaults() -> dict[str, str]:
    """Read the Phase 2 ``PlaneSettings`` *dataclass defaults* directly.

    We intentionally do not call ``load_settings()`` because it touches
    the filesystem (mkdir for workspace/artifact dirs). The dataclass
    defaults are the published contract.
    """
    spec = importlib.util.spec_from_file_location("phase2_config", P2_CONFIG_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("phase2_config", module)
    spec.loader.exec_module(module)
    p2 = module.PlaneSettings
    # dataclass field defaults
    return {
        "ingest_channel": p2.__dataclass_fields__["secure_coding_ingest_channel"].default,
        "ingest_queue":   p2.__dataclass_fields__["secure_coding_ingest_queue"].default,
    }


def _new_pub() -> RedisPublisher:
    pub = RedisPublisher.__new__(RedisPublisher)
    pub.host = "localhost"
    pub.port = 6379
    pub.channel = phase1_settings.REDIS_PUBSUB_CHANNEL
    pub.queue_key = phase1_settings.REDIS_QUEUE_KEY
    pub._memory_backup = collections.deque(maxlen=MAX_BACKUP_SIZE)
    pub._dropped_count = 0
    pub._last_ping_seconds = None
    pub._last_outage_at = None
    pub._was_up = None
    pub.client = fakeredis.FakeRedis(decode_responses=True)
    return pub


class TestKeyContractWithPhase2:
    """Phase 1 publish keys must match the Phase 2 dataclass defaults."""

    def setup_method(self):
        self.p2 = _load_phase2_defaults()

    def test_queue_key_matches_phase2_ingest_queue(self):
        assert phase1_settings.REDIS_QUEUE_KEY == self.p2["ingest_queue"], (
            f"Phase 1 queue {phase1_settings.REDIS_QUEUE_KEY!r} ≠ "
            f"Phase 2 ingest queue {self.p2['ingest_queue']!r} — "
            "BRPOP on the wrong key drops every message silently."
        )

    def test_channel_matches_phase2_ingest_channel(self):
        assert phase1_settings.REDIS_PUBSUB_CHANNEL == self.p2["ingest_channel"], (
            f"Phase 1 channel {phase1_settings.REDIS_PUBSUB_CHANNEL!r} ≠ "
            f"Phase 2 ingest channel {self.p2['ingest_channel']!r}"
        )


class TestDualDelivery:
    """A single ``publish_context`` must produce **both** LPUSH and PUBLISH."""

    def setup_method(self):
        self.pub = _new_pub()
        self.received: list[dict] = []
        # PubSub subscriber so we can assert PUBLISH actually fanned out.
        self.subscriber = self.pub.client.pubsub(ignore_subscribe_messages=True)
        self.subscriber.subscribe(self.pub.channel)
        # Drain the subscribe-ack message immediately.
        self.subscriber.get_message(timeout=0.1)

    def teardown_method(self):
        self.subscriber.close()

    def test_lpush_and_publish_both_fire(self):
        ctx = {"context_id": "ctx-dual-001", "trace_id": "abc123",
               "attack_info": {"cwe_id": "CWE-89"}}
        ok = self.pub.publish_context(ctx)
        assert ok is True

        # 1. LPUSH side
        assert self.pub.client.llen(self.pub.queue_key) == 1
        queued = json.loads(self.pub.client.rpop(self.pub.queue_key))
        assert queued["context_id"] == "ctx-dual-001"
        assert queued["trace_id"] == "abc123"

        # 2. PUBLISH side
        msg = self.subscriber.get_message(timeout=0.5)
        assert msg is not None, "PUBLISH did not fan out to subscribers"
        body = json.loads(msg["data"])
        assert body["context_id"] == "ctx-dual-001"

    def test_publish_is_atomic_per_attempt(self):
        """Both writes happen in the same _try_publish call — no half-state."""
        for i in range(5):
            self.pub.publish_context({"context_id": f"ctx-{i}",
                                      "trace_id": f"t{i}"})
        assert self.pub.client.llen(self.pub.queue_key) == 5


class TestMemoryBackupRoundTrip:
    """Outage → buffer → reconnect → drain must replay onto the SAME keys."""

    def test_drained_messages_land_on_phase2_queue(self, monkeypatch):
        pub = _new_pub()
        # Simulate outage: client unset + reconnect fails.
        pub.client = None
        monkeypatch.setattr(pub, "_connect", lambda: False)
        for i in range(3):
            pub.publish_context({"context_id": f"ctx-{i}", "trace_id": f"t{i}"})
        assert pub.pending_backup_count == 3

        # Recovery: rewire to fakeredis and drain.
        pub.client = fakeredis.FakeRedis(decode_responses=True)
        sent = pub.drain_memory_backup()
        assert sent == 3
        # And — critically — they landed on the *Phase 2* queue key.
        assert pub.client.llen(phase1_settings.REDIS_QUEUE_KEY) == 3


class TestNoStrayKeyDrift:
    """If someone renames the queue/channel on one side only, fail loudly."""

    def test_queue_key_is_namespaced_for_phase2(self):
        assert phase1_settings.REDIS_QUEUE_KEY.startswith("elden:phase2:"), (
            "Queue must remain under the elden:phase2: namespace — "
            "renaming it requires coordinating both phases."
        )

    def test_channel_is_namespaced_for_phase2(self):
        assert phase1_settings.REDIS_PUBSUB_CHANNEL.startswith("elden:phase2:")
