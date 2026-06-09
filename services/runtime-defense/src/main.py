"""
ELDEN RING - Runtime Defense Controller (Phase 1)

FastAPI server that:
  1. Receives security events from ModSecurity audit logs and Falco Sidekick
  2. Normalizes events via adapter pattern
  3. Maps to CWE and source code location
  4. Builds context packages and delivers to Phase 2 via Redis
  5. Executes active defense (rate limit, IP block, endpoint disable)
"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from prometheus_fastapi_instrumentator import Instrumentator

from src import metrics
from src.auth import verify_webhook_token
from src.config import settings
from src.context_builder import build_context
from src.cwe_mapping import map_to_cwe
from src.defense import DefenseManager
from src.logging_config import configure_logging, reset_trace_id, set_trace_id
from src.models import ManualEventRequest, NormalizedEvent, TargetEndpoint
from src.normalizer import EventNormalizer
from src.redis_publisher import RedisPublisher
from src.source_mapper import SourceMapper
from src.throughput import ThroughputTracker

# ── Logging ──────────────────────────────────────────
configure_logging()
logger = logging.getLogger("runtime-defense")

# ── Background drain task ────────────────────────────


async def _drain_loop() -> None:
    """Periodically flush the in-memory Redis backup once Redis is reachable.

    Runs as a single background task. Cancelled on app shutdown.
    """
    while True:
        try:
            await asyncio.sleep(settings.DRAIN_INTERVAL_SECONDS)
            sent = redis_pub.drain_memory_backup()
            if sent:
                logger.info(f"Drain loop flushed {sent} backed-up contexts")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Drain loop iteration failed")


@asynccontextmanager
async def lifespan(_app: "FastAPI"):
    drain_task = asyncio.create_task(_drain_loop())
    logger.info(f"Drain loop started (interval={settings.DRAIN_INTERVAL_SECONDS}s)")
    try:
        yield
    finally:
        drain_task.cancel()
        try:
            await drain_task
        except asyncio.CancelledError:
            pass


# ── App ──────────────────────────────────────────────
app = FastAPI(
    title="ELDEN RING Runtime Defense Controller",
    version="2.0.0",
    description="Phase 1: Event pipeline + active defense",
    lifespan=lifespan,
)
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ── Components ───────────────────────────────────────
normalizer = EventNormalizer()
source_mapper = SourceMapper(settings.ROUTE_MAP_PATH)
redis_pub = RedisPublisher(host=settings.REDIS_HOST, port=settings.REDIS_PORT)
defense_mgr = DefenseManager()
throughput = ThroughputTracker()
_started_at = time.monotonic()

# ── In-memory stores ────────────────────────────────
contexts_store: list[dict] = []
events_store: list[NormalizedEvent] = []
failed_logs: list[dict] = []


# ── Pipeline ─────────────────────────────────────────
async def run_pipeline(event: NormalizedEvent) -> dict:
    """Full pipeline: CWE mapping -> source mapping -> context build -> defense -> Redis."""
    trace_id = uuid.uuid4().hex[:12]
    trace_token = set_trace_id(trace_id)
    pipeline_start = time.perf_counter()

    try:
        events_store.append(event)
        throughput.record()
        metrics.events_total.labels(
            source=event.source,
            attack_category=event.attack_category,
            severity=event.severity,
        ).inc()

        cwe = map_to_cwe(event.attack_category)
        source_map = source_mapper.map(
            event.target_endpoint.method, event.target_endpoint.path
        )

        # Week 11 measurement pipeline — stamp the per-CWE detection time
        # so the cross-phase correlator can subtract from Phase 4's
        # promotion timestamp without sweeping every Loki line.
        metrics.detections_by_cwe_total.labels(
            cwe_id=cwe["cwe_id"], attack_category=event.attack_category
        ).inc()
        metrics.detected_at_unixseconds.labels(
            trace_id=trace_id, cwe_id=cwe["cwe_id"],
        ).set(time.time())

        defense_action = await defense_mgr.handle_defense(event)
        if event.defense_action_taken:
            defense_action = event.defense_action_taken if not defense_action else f"{event.defense_action_taken}+{defense_action}"

        context = build_context(event, cwe, source_map, defense_action, trace_id=trace_id)
        contexts_store.append(context)

        # Sync redis-py call offloaded to a worker thread so the event loop
        # stays responsive while LPUSH+PUBLISH (and any reconnect retry) run.
        publish_start = time.perf_counter()
        await asyncio.to_thread(redis_pub.publish_context, context)
        metrics.redis_publish_duration_seconds.observe(
            time.perf_counter() - publish_start
        )
        metrics.redis_backup_pending.set(redis_pub.pending_backup_count)

        logger.info(
            "pipeline_complete",
            extra={
                "event_id": event.event_id,
                "context_id": context["context_id"],
                "source": event.source,
                "attack_category": event.attack_category,
                "cwe_id": cwe["cwe_id"],
                "defense_action": defense_action,
            },
        )
        return context
    finally:
        metrics.pipeline_duration_seconds.labels(source=event.source).observe(
            time.perf_counter() - pipeline_start
        )
        reset_trace_id(trace_token)


# ── Event Ingestion Endpoints ────────────────────────

@app.post("/api/v1/modsec-events", dependencies=[Depends(verify_webhook_token)])
async def receive_modsec_event(raw_log: dict):
    """Receive ModSecurity audit log (from Fluent Bit or log collector)."""
    try:
        event = normalizer.normalize(raw_log)
        context = await run_pipeline(event)
        return {"status": "processed", "context_id": context["context_id"]}
    except ValueError as e:
        failed_logs.append({"source": "modsecurity", "error": str(e), "raw": raw_log})
        logger.error(f"ModSecurity event parse failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/falco-events", dependencies=[Depends(verify_webhook_token)])
async def receive_falco_event(raw_log: dict):
    """Receive Falco Sidekick webhook event."""
    try:
        event = normalizer.normalize(raw_log)
        context = await run_pipeline(event)
        return {"status": "processed", "context_id": context["context_id"]}
    except ValueError as e:
        failed_logs.append({"source": "falco", "error": str(e), "raw": raw_log})
        logger.error(f"Falco event parse failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/events/manual", dependencies=[Depends(verify_webhook_token)])
async def receive_manual_event(req: ManualEventRequest):
    """Manual event injection for demo purposes."""
    event = NormalizedEvent(
        event_id=f"evt-manual-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc),
        source="manual",
        attack_category=req.attack_category,
        target_endpoint=req.target_endpoint,
        payload_sample=req.payload_sample,
        source_ip=req.source_ip,
        blocked=req.blocked,
        severity=req.severity,
        requires_patch=req.requires_patch,
        defense_action_taken=req.defense_action_taken,
    )
    context = await run_pipeline(event)
    return {"status": "processed", "context_id": context["context_id"]}


# ── Query Endpoints ──────────────────────────────────

@app.get("/api/v1/contexts/{context_id}")
async def get_context(context_id: str):
    for ctx in contexts_store:
        if ctx["context_id"] == context_id:
            return ctx
    raise HTTPException(status_code=404, detail="Context not found")


@app.get("/api/v1/contexts/latest")
async def get_latest_contexts(limit: int = 20):
    return {"contexts": contexts_store[-limit:], "total": len(contexts_store)}


@app.get("/api/v1/defense/actions")
async def get_defense_actions(limit: int = 50):
    return {"actions": defense_mgr.action_history[-limit:], "total": len(defense_mgr.action_history)}


@app.get("/api/v1/defense/stats")
async def get_defense_stats():
    return defense_mgr.get_stats()


@app.get("/api/v1/events/stats")
async def get_event_stats():
    by_source: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for evt in events_store:
        by_source[evt.source] = by_source.get(evt.source, 0) + 1
        by_category[evt.attack_category] = by_category.get(evt.attack_category, 0) + 1
        by_severity[evt.severity] = by_severity.get(evt.severity, 0) + 1
    return {
        "total_events": len(events_store),
        "by_source": by_source,
        "by_category": by_category,
        "by_severity": by_severity,
        "failed_parses": len(failed_logs),
    }


# ── Health Checks ────────────────────────────────────

@app.get("/healthz")
async def health():
    return {"status": "ok"}


@app.get("/readyz")
async def ready():
    """Readiness: signals whether the controller can accept events.

    Always returns 200 as long as adapters and the route map are loaded.
    Redis being down does NOT fail readiness — events are buffered to an
    in-memory backup and drained when Redis recovers. Failing readiness
    here would cause Falco/ModSec webhooks to be cut off entirely, which
    is strictly worse than transient Redis loss.

    See ``/diagnostics`` for subsystem detail.
    """
    return {
        "status": "ready",
        "adapters": len(normalizer.adapters),
        "routes_loaded": len(source_mapper.route_map),
        "redis_connected": redis_pub.is_connected(),
        "backup_pending": redis_pub.pending_backup_count,
    }


def _read_hpa_replicas() -> dict:
    """Best-effort HPA replica lookup. Returns {current,desired} or {error}.

    Skipped (returns ``{"available": False}``) when in-cluster config is
    not loadable — e.g. local docker-compose runs. Failures here must
    never bubble up into a 5xx for /diagnostics, since the watcher polls
    it once per second across the entire load test.
    """
    try:
        from kubernetes import client, config  # local import: heavy + optional path
        try:
            config.load_incluster_config()
        except config.ConfigException:
            return {"available": False, "reason": "not-in-cluster"}
        api = client.AutoscalingV2Api()
        hpa = api.read_namespaced_horizontal_pod_autoscaler(
            name="runtime-defense-controller",
            namespace=settings.K8S_NAMESPACE,
        )
        return {
            "available": True,
            "current_replicas": hpa.status.current_replicas or 0,
            "desired_replicas": hpa.status.desired_replicas or 0,
            "min_replicas": hpa.spec.min_replicas,
            "max_replicas": hpa.spec.max_replicas,
        }
    except Exception as e:  # noqa: BLE001 — diagnostics must not 5xx
        return {"available": False, "reason": f"{type(e).__name__}: {e}"}


@app.get("/diagnostics")
async def diagnostics():
    """Detailed subsystem state for operators. Not used by K8s probes.

    Reads cached Redis state instead of doing a fresh ping so that
    high-frequency observability pollers (e.g. the reliability watcher
    at 1Hz) don't block on the 2s Redis socket timeout during an
    outage — which would create exactly the blind window the watcher
    is meant to capture. ``/readyz`` still does an active probe.
    """
    connected = redis_pub.up_cached
    last_ping_s = redis_pub.last_ping_seconds
    last_outage = redis_pub.last_outage_at
    return {
        # Preserved for back-compat with existing consumers (e.g. /readyz).
        "redis": {
            "host": redis_pub.host,
            "port": redis_pub.port,
            "connected": connected,
            "up": connected,
            "last_ping_ms": int(last_ping_s * 1000) if last_ping_s is not None else None,
            "last_outage_at": last_outage.isoformat() if last_outage else None,
            "backup_pending": redis_pub.pending_backup_count,
            "backup_dropped_total": redis_pub.dropped_count,
        },
        "backup_queue": {
            "length": redis_pub.pending_backup_count,
            "capacity": settings.MEMORY_BACKUP_MAX_SIZE,
            "drops_total": redis_pub.dropped_count,
        },
        "throughput": {
            "events_per_sec_1m": round(throughput.events_per_sec(), 3),
            "events_processed_total": throughput.total,
        },
        "hpa": _read_hpa_replicas(),
        "pipeline": {
            "adapters_loaded": len(normalizer.adapters),
            "routes_loaded": len(source_mapper.route_map),
            "events_processed": len(events_store),
            "contexts_built": len(contexts_store),
            "failed_parses": len(failed_logs),
        },
        "uptime_sec": int(time.monotonic() - _started_at),
        "auth_enforced": bool(settings.WEBHOOK_AUTH_TOKEN),
    }
