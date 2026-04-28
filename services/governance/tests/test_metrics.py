from prometheus_client import REGISTRY

from src.metrics import (
    active_incidents,
    incidents_total,
    policy_violations_total,
    promotion_decisions_total,
    rollbacks_total,
)


def _value(metric, **labels):
    return metric.labels(**labels)._value.get()


def test_incidents_total_records_per_stage_and_risk():
    incidents_total.labels(stage="policy_check", risk="high").inc()
    incidents_total.labels(stage="policy_check", risk="high").inc()
    incidents_total.labels(stage="completed", risk="low").inc()
    assert _value(incidents_total, stage="policy_check", risk="high") >= 2
    assert _value(incidents_total, stage="completed", risk="low") >= 1


def test_active_incidents_inc_dec():
    before = _value(active_incidents, risk="medium")
    active_incidents.labels(risk="medium").inc()
    active_incidents.labels(risk="medium").inc()
    active_incidents.labels(risk="medium").dec()
    assert _value(active_incidents, risk="medium") == before + 1


def test_policy_violations_per_policy():
    policy_violations_total.labels(policy="elden-rbac-escalation-guard").inc()
    assert _value(policy_violations_total, policy="elden-rbac-escalation-guard") >= 1


def test_promotion_decisions_buckets():
    for d in ("auto", "manual_pause", "rejected"):
        promotion_decisions_total.labels(decision=d).inc()
    assert _value(promotion_decisions_total, decision="auto") >= 1
    assert _value(promotion_decisions_total, decision="manual_pause") >= 1
    assert _value(promotion_decisions_total, decision="rejected") >= 1


def test_rollbacks_total_buckets():
    rollbacks_total.labels(reason="slo_breach").inc()
    rollbacks_total.labels(reason="manual").inc()
    assert _value(rollbacks_total, reason="slo_breach") >= 1
    assert _value(rollbacks_total, reason="manual") >= 1


def test_metrics_registered_in_default_registry():
    names = {m.name for m in REGISTRY.collect()}
    assert "governance_incidents" in names or "governance_incidents_total" in names
    assert "governance_active_incidents" in names
    assert "governance_policy_violations" in names or "governance_policy_violations_total" in names
    assert "governance_rollbacks" in names or "governance_rollbacks_total" in names
    assert "governance_promotion_decisions" in names or "governance_promotion_decisions_total" in names
