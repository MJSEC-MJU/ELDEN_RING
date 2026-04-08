"""Tests for context package builder."""

from datetime import datetime, timezone
from src.models import NormalizedEvent, TargetEndpoint
from src.context_builder import build_context


def _make_event(**overrides) -> NormalizedEvent:
    defaults = {
        "event_id": "evt-test-001",
        "timestamp": datetime(2026, 4, 8, 14, 30, 0, tzinfo=timezone.utc),
        "source": "modsecurity",
        "attack_category": "SQL Injection",
        "target_endpoint": TargetEndpoint(method="POST", path="/api/login"),
        "payload_sample": "username=admin' OR 1=1--",
        "source_ip": "192.168.1.100",
        "blocked": True,
        "severity": "CRITICAL",
        "raw_rule_id": "942100",
    }
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


CWE_89 = {
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
    "owasp": "A03:2021",
}

SOURCE_MAP = {
    "file": "app.py",
    "function": "login_handler",
    "line_start": 14,
    "line_end": 27,
}


class TestContextBuilder:
    def test_full_context(self):
        event = _make_event()
        ctx = build_context(event, CWE_89, SOURCE_MAP, "rate_limit+ip_blocked")

        assert ctx["context_id"] == "ctx-evt-test-001"
        assert ctx["attack_info"]["category"] == "SQL Injection"
        assert ctx["attack_info"]["cwe_id"] == "CWE-89"
        assert ctx["attack_info"]["blocked"] is True
        assert ctx["target"]["source_mapping"]["file"] == "app.py"
        assert ctx["metadata"]["defense_action_taken"] == "rate_limit+ip_blocked"
        assert ctx["metadata"]["requires_patch"] is True

    def test_context_without_source_map(self):
        event = _make_event()
        ctx = build_context(event, CWE_89, None)
        assert ctx["target"]["source_mapping"] is None

    def test_context_unknown_cwe(self):
        event = _make_event(attack_category="Unknown")
        unknown = {"cwe_id": "UNKNOWN", "cwe_name": "Unmapped", "owasp": "UNKNOWN"}
        ctx = build_context(event, unknown, None)
        assert ctx["metadata"]["requires_patch"] is False
