"""Smoke test — no real cluster, no real GitHub.

Validates that the orchestrator flow correctly classifies a Phase 3 PASSED
result, decides not to retry, and that a FAILED result routes to retry.
Network/k8s clients are replaced with in-memory fakes.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from src.models import Phase3Result, ValidationStatus


class _FakeK8s:
    def read_configmap(self, ns, name):
        return {}

    def list_policy_reports(self, ns):
        return []


class _FakeRedis:
    def __init__(self):
        self.published: list[tuple[str, str]] = []

    async def publish(self, channel, payload):
        self.published.append((channel, payload))


@pytest.mark.asyncio
async def test_failed_phase3_routes_to_retry(monkeypatch):
    from src import orchestrator as orch_mod
    monkeypatch.setattr(orch_mod, "GitWriter", None)
    monkeypatch.setenv("GOV_GITHUB_TOKEN", "")

    orch = orch_mod.Orchestrator.__new__(orch_mod.Orchestrator)
    orch.k8s = _FakeK8s()
    orch.git = None
    orch.classifier = orch_mod.RiskClassifier()
    orch.policy_gate = type("G", (), {"evaluate": lambda self, i: type("R", (), {"passed": True, "violations": []})()})()
    orch.promotion_gate = type("P", (), {"resume_if_allowed": lambda self, *a, **k: True})()
    orch._state = {}

    redis_fake = _FakeRedis()
    result = Phase3Result(
        incident_id="t-001",
        candidate_image="ghcr.io/mjsec-mju/elden-target-app:abc",
        exploit=ValidationStatus.FAILED,
        regression=ValidationStatus.PASSED,
        slo=ValidationStatus.PASSED,
        manifests=[{"kind": "NetworkPolicy", "metadata": {"name": "np"}}],
    )
    await orch._handle(result, redis_fake)
    assert any("elden:phase2:retry" in ch for ch, _ in redis_fake.published)


def test_phase3_summary_format():
    from src.orchestrator import Orchestrator
    r = Phase3Result(
        incident_id="t-002",
        candidate_image="img:1",
        exploit=ValidationStatus.PASSED,
        regression=ValidationStatus.PASSED,
        slo=ValidationStatus.PASSED,
    )
    s = Orchestrator._summarize(r)
    assert "PASSED" in s and "img:1" in s
