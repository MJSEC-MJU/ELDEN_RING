"""Tests for EventNormalizer adapter routing."""

import pytest
from src.normalizer import EventNormalizer


class TestEventNormalizer:
    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_routes_modsec_event(self):
        raw = {
            "transaction": {
                "time": "2026-04-08T14:30:00Z",
                "remote_address": "1.2.3.4",
                "request": {"method": "POST", "uri": "/api/login", "body": "test"},
            },
            "audit_data": {
                "messages": [{"details": {"ruleId": "942100", "severity": "CRITICAL"}}]
            },
        }
        event = self.normalizer.normalize(raw)
        assert event.source == "modsecurity"

    def test_routes_falco_event(self):
        raw = {
            "output": "Shell spawned",
            "priority": "Critical",
            "rule": "Shell Rule",
            "time": "2026-04-08T14:30:00Z",
            "output_fields": {"k8s.pod.name": "test-pod"},
            "tags": ["shell"],
        }
        event = self.normalizer.normalize(raw)
        assert event.source == "falco"

    def test_raises_for_unknown_log(self):
        with pytest.raises(ValueError, match="No adapter"):
            self.normalizer.normalize({"unknown": "format"})
