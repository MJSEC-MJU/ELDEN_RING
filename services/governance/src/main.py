import asyncio
import logging

from fastapi import FastAPI, HTTPException
from prometheus_fastapi_instrumentator import Instrumentator

from .config import settings
from .k8s_client import K8sClient
from .models import PromotionRequest
from .orchestrator import Orchestrator
from .rollback_watcher import RollbackWatcher

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="ELDEN RING — Governance Orchestrator", version="0.1.0")
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

_k8s = K8sClient()
_orch = Orchestrator(_k8s)
_watcher = RollbackWatcher(
    prom_url=settings.prometheus_url,
    gate=_orch.promotion_gate,
    namespace=settings.canary_namespace,
    rollout="target-app",
    err_threshold=settings.canary_error_rate_threshold,
    p99_threshold_ms=settings.canary_latency_p99_ms_threshold,
)


@app.on_event("startup")
async def _startup() -> None:
    asyncio.create_task(_orch.run())
    asyncio.create_task(_watcher.run(service="target-app-canary"))
    logger.info("governance orchestrator started")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict[str, str]:
    return {"status": "ready"}


@app.get("/incidents", response_model=list[PromotionRequest])
async def incidents() -> list[PromotionRequest]:
    return _orch.snapshot()


@app.post("/incidents/{incident_id}/approve")
async def approve(incident_id: str, approver: str) -> dict[str, str]:
    state = {r.incident_id: r for r in _orch.snapshot()}
    req = state.get(incident_id)
    if not req:
        raise HTTPException(404, "incident not found")
    _orch.promotion_gate.approve(req.rollout_namespace, req.rollout_name, approver)
    return {"status": "approved", "incident": incident_id, "by": approver}


@app.post("/incidents/{incident_id}/rollback")
async def rollback(incident_id: str, reason: str = "manual") -> dict[str, str]:
    state = {r.incident_id: r for r in _orch.snapshot()}
    req = state.get(incident_id)
    if not req:
        raise HTTPException(404, "incident not found")
    _orch.promotion_gate.abort(req.rollout_namespace, req.rollout_name, reason)
    return {"status": "rolled_back", "incident": incident_id, "reason": reason}
