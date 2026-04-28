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
