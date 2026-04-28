"""
ELDEN RING - Runtime Defense Controller (Phase 1)

FastAPI server that:
  1. Receives security events from ModSecurity audit logs and Falco Sidekick
  2. Normalizes events via adapter pattern
  3. Maps to CWE and source code location
  4. Builds context packages and delivers to Phase 2 via Redis
  5. Executes active defense (rate limit, IP block, endpoint disable)
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from prometheus_fastapi_instrumentator import Instrumentator

from src.auth import verify_webhook_token
from src.config import settings
from src.models import NormalizedEvent, TargetEndpoint, ManualEventRequest
from src.normalizer import EventNormalizer
from src.cwe_mapping import map_to_cwe
from src.source_mapper import SourceMapper
from src.context_builder import build_context
from src.redis_publisher import RedisPublisher
from src.defense import DefenseManager

# ── Logging ──────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("runtime-defense")

# ── App ──────────────────────────────────────────────
app = FastAPI(
    title="ELDEN RING Runtime Defense Controller",
    version="2.0.0",
    description="Phase 1: Event pipeline + active defense",
)
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ── Components ───────────────────────────────────────
normalizer = EventNormalizer()
source_mapper = SourceMapper(settings.ROUTE_MAP_PATH)
redis_pub = RedisPublisher(host=settings.REDIS_HOST, port=settings.REDIS_PORT)
defense_mgr = DefenseManager()

# ── In-memory stores ────────────────────────────────
contexts_store: list[dict] = []
events_store: list[NormalizedEvent] = []
failed_logs: list[dict] = []


# ── Pipeline ─────────────────────────────────────────
async def run_pipeline(event: NormalizedEvent) -> dict:
    """Full pipeline: CWE mapping -> source mapping -> context build -> defense -> Redis."""
    events_store.append(event)

    # Step 2: CWE mapping
    cwe = map_to_cwe(event.attack_category)

    # Step 3: Source code mapping
    source_map = source_mapper.map(
        event.target_endpoint.method, event.target_endpoint.path
    )

    # Step 4 (parallel): Active defense
    defense_action = await defense_mgr.handle_defense(event)

    # Step 5: Build context package
    context = build_context(event, cwe, source_map, defense_action)
    contexts_store.append(context)

    # Step 6: Deliver to Phase 2 via Redis
    redis_pub.publish_context(context)

    logger.info(
        f"Pipeline complete: {event.event_id} | "
        f"{event.source} | {event.attack_category} | "
        f"{cwe['cwe_id']} | defense={defense_action}"
    )
    return context


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
        blocked=False,
        severity=req.severity,
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
    return {"status": "ready", "adapters": 2, "routes_loaded": len(source_mapper.route_map)}
