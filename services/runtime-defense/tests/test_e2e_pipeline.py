"""End-to-end tests for the runtime-defense pipeline.

Drives the FastAPI app through TestClient with a fakeredis backend
so the full path runs: ingestion endpoint -> auth -> normalize ->
CWE map -> source map -> defense -> context build -> Redis publish.

Source-of-truth checks:
- Response payload contains the generated context_id.
- /api/v1/contexts/{id} returns the same context with the expected
  CWE / source-mapping / metadata.trace_id.
- The fake Redis queue has the same payload (Phase 2 contract).
- Defense escalation across repeated attacks from one IP.
"""

import json

import fakeredis
import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.main import app, contexts_store, defense_mgr, events_store, redis_pub


VALID_TOKEN = "e2e-test-token"


def _modsec_log(rule_id: int, source_ip: str, severity: str = "CRITICAL") -> dict:
    return {
        "transaction": {
            "time": "2026-04-08T14:30:00Z",
            "remote_address": source_ip,
            "request": {
                "method": "POST",
                "uri": "/api/login",
                "body": "username=admin' OR 1=1--",
            },
        },
        "audit_data": {
            "messages": [{"details": {"ruleId": rule_id, "severity": severity}}]
        },
    }


def _falco_log(tag: str, source_ip: str | None = None) -> dict:
    return {
        "rule": "ELDEN Test Rule",
        "priority": "Critical",
        "time": "2026-04-08T14:30:00Z",
        "output": "Test event",
        "output_fields": {
            "k8s.pod.name": "target-app-abc",
            "k8s.ns.name": "elden-production",
            **({"fd.sip": source_ip} if source_ip else {}),
        },
        "tags": [tag],
    }


@pytest.fixture
def client(monkeypatch):
    """TestClient with fakeredis swapped in and shared state cleared."""
    monkeypatch.setattr(settings, "WEBHOOK_AUTH_TOKEN", VALID_TOKEN)

    # Replace the live Redis client with fakeredis so LPUSH/PUBLISH succeed.
    # Also seed the cached up-state so /diagnostics — which now reads cached
    # state to stay non-blocking during outages — reports the swap honestly.
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_pub, "client", fake)
    monkeypatch.setattr(redis_pub, "_was_up", True)

    # The pipeline accumulates state in module-level lists; reset them so
    # each test starts clean.
    contexts_store.clear()
    events_store.clear()
    defense_mgr.action_history.clear()
    defense_mgr.ip_attack_count.clear()
    defense_mgr.endpoint_attack_count.clear()
    defense_mgr._blocked_ips.clear()
    defense_mgr._disabled_endpoints.clear()
    redis_pub._memory_backup.clear()

    with TestClient(app) as c:
        yield c, fake


def _auth(headers: dict | None = None) -> dict:
    return {**(headers or {}), "Authorization": f"Bearer {VALID_TOKEN}"}


class TestModSecPipeline:
    def test_sqli_full_pipeline(self, client):
        c, fake = client
        r = c.post(
            "/api/v1/modsec-events",
            json=_modsec_log(942100, "10.0.0.1"),
            headers=_auth(),
        )
        assert r.status_code == 200
        ctx_id = r.json()["context_id"]

        # Round-trip through the in-memory store
        ctx = c.get(f"/api/v1/contexts/{ctx_id}").json()
        assert ctx["attack_info"]["cwe_id"] == "CWE-89"
        assert ctx["attack_info"]["category"] == "SQL Injection"
        assert ctx["metadata"]["detection_source"] == "modsecurity"
        assert ctx["metadata"]["trace_id"]  # 12-hex
        assert len(ctx["metadata"]["trace_id"]) == 12
        assert ctx["metadata"]["requires_patch"] is True

        # Redis dual delivery
        queued = fake.rpop(redis_pub.queue_key)
        assert json.loads(queued)["context_id"] == ctx_id


class TestFalcoPipeline:
    def test_shell_event_full_pipeline(self, client):
        c, fake = client
        r = c.post(
            "/api/v1/falco-events",
            json=_falco_log("shell"),
            headers=_auth(),
        )
        assert r.status_code == 200
        ctx_id = r.json()["context_id"]

        ctx = c.get(f"/api/v1/contexts/{ctx_id}").json()
        assert ctx["attack_info"]["category"] == "Shell Execution"
        assert ctx["metadata"]["detection_source"] == "falco"
        assert ctx["metadata"]["severity"] == "CRITICAL"

        assert fake.llen(redis_pub.queue_key) == 1


class TestManualPipeline:
    def test_manual_injection_full_pipeline(self, client):
        c, fake = client
        r = c.post(
            "/api/v1/events/manual",
            json={
                "attack_category": "Cross-Site Scripting",
                "target_endpoint": {"method": "GET", "path": "/api/search"},
                "payload_sample": "<script>alert(1)</script>",
                "source_ip": "192.168.1.50",
                "severity": "HIGH",
            },
            headers=_auth(),
        )
        assert r.status_code == 200
        ctx_id = r.json()["context_id"]

        ctx = c.get(f"/api/v1/contexts/{ctx_id}").json()
        assert ctx["attack_info"]["cwe_id"] == "CWE-79"
        assert ctx["metadata"]["detection_source"] == "manual"
        assert ctx["attack_info"]["payload_sample"] == "<script>alert(1)</script>"


class TestDefenseEscalation:
    def test_repeated_ip_triggers_block(self, client):
        c, _ = client
        # 3 attacks from the same IP — IP_BLOCK_THRESHOLD default.
        # First with WARNING so severity-based escalation does not fire early.
        for i in range(3):
            r = c.post(
                "/api/v1/modsec-events",
                json=_modsec_log(942100 + i, "10.0.0.99", severity="WARNING"),
                headers=_auth(),
            )
            assert r.status_code == 200

        stats = c.get("/api/v1/defense/stats").json()
        assert "10.0.0.99" in stats["blocked_ips"]
        assert stats["ip_attack_counts"]["10.0.0.99"] == 3

    def test_critical_event_blocks_ip_immediately(self, client):
        c, _ = client
        c.post(
            "/api/v1/modsec-events",
            json=_modsec_log(942100, "203.0.113.7", severity="CRITICAL"),
            headers=_auth(),
        )
        stats = c.get("/api/v1/defense/stats").json()
        # CRITICAL severity → IP block on first event.
        assert "203.0.113.7" in stats["blocked_ips"]


class TestAuthOnPipeline:
    def test_pipeline_blocked_without_token(self, client):
        c, fake = client
        r = c.post("/api/v1/modsec-events", json=_modsec_log(942100, "1.1.1.1"))
        assert r.status_code == 401
        # No state side-effects from a rejected request.
        assert fake.llen(redis_pub.queue_key) == 0

    def test_diagnostics_reports_auth_state(self, client):
        c, _ = client
        d = c.get("/diagnostics").json()
        assert d["auth_enforced"] is True
        assert d["redis"]["connected"] is True
