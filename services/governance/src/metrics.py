from prometheus_client import Counter, Gauge


incidents_total = Counter(
    "governance_incidents_total",
    "Number of incidents handled by the orchestrator, partitioned by stage and risk.",
    ["stage", "risk"],
)

active_incidents = Gauge(
    "governance_active_incidents",
    "Incidents currently in flight (not yet completed or rolled back).",
    ["risk"],
)

policy_violations_total = Counter(
    "governance_policy_violations_total",
    "Total Kyverno policy violations seen by the policy gate, by policy name.",
    ["policy"],
)

rollbacks_total = Counter(
    "governance_rollbacks_total",
    "Total rollouts aborted by the orchestrator, by reason.",
    ["reason"],
)

promotion_decisions_total = Counter(
    "governance_promotion_decisions_total",
    "Promotion gate decisions: auto / manual-pause / rejected.",
    ["decision"],
)
