"""Tests for webhook authentication on event-injection endpoints."""

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.main import app


VALID_TOKEN = "test-token-abc123"

MODSEC_PAYLOAD = {
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
                    "message": "SQL Injection",
                }
            }
        ]
    },
}


@pytest.fixture
def client_with_auth(monkeypatch):
    """Token configured — auth enforced."""
    monkeypatch.setattr(settings, "WEBHOOK_AUTH_TOKEN", VALID_TOKEN)
    return TestClient(app)


@pytest.fixture
def client_without_auth(monkeypatch):
    """Token empty — auth disabled (dev mode)."""
    monkeypatch.setattr(settings, "WEBHOOK_AUTH_TOKEN", "")
    return TestClient(app)


class TestAuthEnforced:
    def test_missing_header_returns_401(self, client_with_auth):
        r = client_with_auth.post("/api/v1/modsec-events", json=MODSEC_PAYLOAD)
        assert r.status_code == 401
        assert r.headers.get("www-authenticate") == "Bearer"

    def test_non_bearer_scheme_returns_401(self, client_with_auth):
        r = client_with_auth.post(
            "/api/v1/modsec-events",
            json=MODSEC_PAYLOAD,
            headers={"Authorization": f"Basic {VALID_TOKEN}"},
        )
        assert r.status_code == 401

    def test_wrong_token_returns_403(self, client_with_auth):
        r = client_with_auth.post(
            "/api/v1/modsec-events",
            json=MODSEC_PAYLOAD,
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert r.status_code == 403

    def test_valid_token_accepted(self, client_with_auth):
        r = client_with_auth.post(
            "/api/v1/modsec-events",
            json=MODSEC_PAYLOAD,
            headers={"Authorization": f"Bearer {VALID_TOKEN}"},
        )
        # Auth must pass — pipeline-level errors (5xx) are a separate concern;
        # the assertion is that no 4xx (auth-side) is returned.
        assert r.status_code < 400 or r.status_code >= 500

    def test_falco_endpoint_protected(self, client_with_auth):
        r = client_with_auth.post("/api/v1/falco-events", json={})
        assert r.status_code == 401

    def test_manual_endpoint_protected(self, client_with_auth):
        r = client_with_auth.post("/api/v1/events/manual", json={})
        assert r.status_code == 401

    def test_health_endpoints_open(self, client_with_auth):
        assert client_with_auth.get("/healthz").status_code == 200
        assert client_with_auth.get("/readyz").status_code == 200

    def test_query_endpoints_open(self, client_with_auth):
        # Query (read-only) endpoints intentionally remain open per Q2 decision.
        # Tightening these is tracked as a follow-up.
        assert client_with_auth.get("/api/v1/events/stats").status_code == 200


class TestAuthDisabled:
    def test_no_token_required_when_disabled(self, client_without_auth):
        r = client_without_auth.post("/api/v1/modsec-events", json=MODSEC_PAYLOAD)
        assert r.status_code < 400 or r.status_code >= 500
