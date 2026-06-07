"""Prometheus business metrics for the runtime-defense pipeline.

Exposed via the ``/metrics`` endpoint set up by
``prometheus-fastapi-instrumentator`` in ``main.py``. The instrumentator
already provides per-route HTTP counters/histograms; the metrics here
are pipeline-internal (events received, defense actions, Redis state).
"""

from prometheus_client import Counter, Gauge, Histogram


events_total = Counter(
    "runtime_defense_events_total",
    "Security events received and normalized by the pipeline.",
    ["source", "attack_category", "severity"],
)


defense_actions_total = Counter(
    "runtime_defense_actions_total",
    "Active defense actions executed against a target.",
    ["action"],
)


pipeline_duration_seconds = Histogram(
    "runtime_defense_pipeline_duration_seconds",
    "End-to-end runtime of run_pipeline (normalize -> defense -> Redis).",
    ["source"],
)


redis_publish_duration_seconds = Histogram(
    "runtime_defense_redis_publish_seconds",
    "Time spent in publish_context (includes connect retry on cold path).",
)


redis_backup_pending = Gauge(
    "runtime_defense_redis_backup_pending",
    "Contexts buffered in memory awaiting Redis recovery.",
)


redis_backup_dropped_total = Counter(
    "runtime_defense_redis_backup_dropped_total",
    "Contexts dropped because the in-memory backup queue was full.",
)


redis_up = Gauge(
    "runtime_defense_redis_up",
    "1 if last Redis ping succeeded, 0 otherwise.",
)


redis_last_ping_seconds = Gauge(
    "runtime_defense_redis_last_ping_seconds",
    "Latency of the last Redis ping in seconds (NaN until first probe).",
)


# Phase 1 Week 11 — CWE-labelled detection timestamps for the
# cross-phase trace_id correlator. Counter: count of detections per
# CWE (used as denominator). Gauge: unix-seconds at which Phase 1
# stamped "detected" — exported under the trace_id label so the
# Loki/Prometheus correlator can subtract from Phase 4's promotion
# timestamp. Note: trace_id cardinality is high but bounded by the
# attack rate within Prometheus's local retention window.
detections_by_cwe_total = Counter(
    "runtime_defense_detections_by_cwe_total",
    "Number of attacks detected by Phase 1, labelled by CWE.",
    ["cwe_id", "attack_category"],
)


detected_at_unixseconds = Gauge(
    "runtime_defense_detected_at_unixseconds",
    "Unix-seconds when Phase 1 emitted a context for this trace_id.",
    ["trace_id", "cwe_id"],
)
