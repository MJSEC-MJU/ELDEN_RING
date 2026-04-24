"""Tests for ModSecurity and Falco adapters."""

import pytest
from src.adapters.modsecurity import ModSecurityAdapter
from src.adapters.falco import FalcoAdapter


# ── ModSecurity Adapter ──────────────────────────────

MODSEC_SQLI_LOG = {
    "transaction": {
        "time": "2026-04-08T14:30:00Z",
        "remote_address": "192.168.1.100",
        "request": {
            "method": "POST",
            "uri": "/api/login",
            "body": "username=admin' OR 1=1--",
        },
    },
    "audit_data": {
        "messages": [
            {
                "details": {
                    "ruleId": "942100",
                    "severity": "CRITICAL",
                    "message": "SQL Injection Attack Detected",
                }
            }
        ]
    },
}

MODSEC_XSS_LOG = {
    "transaction": {
        "time": "2026-04-08T14:31:00Z",
        "remote_address": "10.0.0.50",
        "request": {
            "method": "GET",
            "uri": "/api/search",
            "query_string": "q=<script>alert(1)</script>",
        },
    },
    "audit_data": {
        "messages": [
            {
                "details": {
                    "ruleId": "941100",
                    "severity": "WARNING",
                    "message": "XSS Attack Detected",
                }
            }
        ]
    },
}

MODSEC_PATH_TRAVERSAL_LOG = {
    "transaction": {
        "time": "2026-04-08T14:32:00Z",
        "remote_address": "172.16.0.10",
        "request": {
            "method": "GET",
            "uri": "/api/file",
            "query_string": "name=../../etc/passwd",
        },
    },
    "audit_data": {
        "messages": [
            {
                "details": {
                    "ruleId": "930100",
                    "severity": "CRITICAL",
                    "message": "Path Traversal Attack Detected",
                }
            }
        ]
    },
}


class TestModSecurityAdapter:
    def setup_method(self):
        self.adapter = ModSecurityAdapter()

    def test_can_handle_valid_log(self):
        assert self.adapter.can_handle(MODSEC_SQLI_LOG) is True

    def test_can_handle_invalid_log(self):
        assert self.adapter.can_handle({"random": "data"}) is False
        assert self.adapter.can_handle({"transaction": {}}) is False

    def test_parse_sqli(self):
        event = self.adapter.parse(MODSEC_SQLI_LOG)
        assert event.source == "modsecurity"
        assert event.attack_category == "SQL Injection"
        assert event.target_endpoint.method == "POST"
        assert event.target_endpoint.path == "/api/login"
        assert event.source_ip == "192.168.1.100"
        assert event.blocked is True
        assert event.severity == "CRITICAL"
        assert "942100" in event.raw_rule_id

    def test_parse_xss(self):
        event = self.adapter.parse(MODSEC_XSS_LOG)
        assert event.attack_category == "Cross-Site Scripting"
        assert event.target_endpoint.method == "GET"
        assert event.severity == "HIGH"

    def test_parse_path_traversal(self):
        event = self.adapter.parse(MODSEC_PATH_TRAVERSAL_LOG)
        assert event.attack_category == "Path Traversal"
        assert event.severity == "CRITICAL"
        assert "930100" in event.raw_rule_id


# ── Falco Adapter ────────────────────────────────────

FALCO_SHELL_EVENT = {
    "output": "Shell spawned in production container",
    "priority": "Critical",
    "rule": "ELDEN Shell Spawned in Production",
    "time": "2026-04-08T14:30:00.000000000Z",
    "output_fields": {
        "k8s.ns.name": "elden-production",
        "k8s.pod.name": "target-app-abc123",
        "proc.cmdline": "bash",
    },
    "tags": ["shell"],
}

FALCO_NETWORK_EVENT = {
    "output": "Unexpected outbound connection",
    "priority": "Warning",
    "rule": "ELDEN Unexpected Outbound Connection",
    "time": "2026-04-08T14:35:00.000000000Z",
    "output_fields": {
        "k8s.ns.name": "elden-production",
        "k8s.pod.name": "target-app-def456",
        "fd.sip": "10.0.0.99",
    },
    "tags": ["network"],
}


class TestFalcoAdapter:
    def setup_method(self):
        self.adapter = FalcoAdapter()

    def test_can_handle_valid_log(self):
        assert self.adapter.can_handle(FALCO_SHELL_EVENT) is True

    def test_can_handle_invalid_log(self):
        assert self.adapter.can_handle({"random": "data"}) is False

    def test_parse_shell_event(self):
        event = self.adapter.parse(FALCO_SHELL_EVENT)
        assert event.source == "falco"
        assert event.attack_category == "Shell Execution"
        assert event.severity == "CRITICAL"
        assert event.blocked is False
        assert event.raw_rule_id == "ELDEN Shell Spawned in Production"

    def test_parse_network_event(self):
        event = self.adapter.parse(FALCO_NETWORK_EVENT)
        assert event.attack_category == "Suspicious Network"
        assert event.severity == "MEDIUM"
        assert event.source_ip == "10.0.0.99"
