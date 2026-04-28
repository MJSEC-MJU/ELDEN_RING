from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .redis_subscriber import RedisSubscriber
from .state import PipelineState
from .ws_manager import WSManager


logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

REDIS_URL = os.environ.get("MONITOR_REDIS_URL", "redis://redis-master.elden-monitoring:6379/0")
GOV_URL = os.environ.get("MONITOR_GOVERNANCE_URL", "http://governance-controller.elden-governance:8080")
STATIC_DIR = Path(__file__).parent / "static"

state = PipelineState()
ws_mgr = WSManager()
app = FastAPI(title="ELDEN RING — Pipeline Monitor")


async def _on_message(channel: str, payload: dict) -> None:
    event = state.push_event(channel, payload)
    await ws_mgr.broadcast({"type": "event", "event": event})
    rec = state.incidents.get(event["incident_id"]) if event["incident_id"] else None
    if rec:
        await ws_mgr.broadcast({
            "type": "incident_upsert",
            "incident": {
                "incident_id": rec.incident_id,
                "stage": rec.phase4_stage,
                "risk": rec.risk,
                "cwe_id": rec.cwe_id,
                "severity": rec.severity,
                "branch": rec.branch,
                "started_at": rec.started_at,
                "last_at": rec.last_at,
            },
        })


async def _governance_poller() -> None:
    while True:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(f"{GOV_URL}/incidents")
                if r.status_code == 200:
                    state.update_phase4(r.json())
        except Exception:
            pass
        await asyncio.sleep(5)


@app.on_event("startup")
async def _startup() -> None:
    sub = RedisSubscriber(REDIS_URL, _on_message)
    asyncio.create_task(sub.run())
    asyncio.create_task(_governance_poller())


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/api/incidents")
async def get_incidents() -> JSONResponse:
    return JSONResponse(state.snapshot_incidents())


@app.get("/api/events")
async def get_events() -> JSONResponse:
    return JSONResponse(list(state.events))


@app.get("/api/stats")
async def get_stats() -> JSONResponse:
    return JSONResponse(state.stats())


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws_mgr.connect(ws)
    try:
        await ws.send_json({"type": "snapshot", "incidents": state.snapshot_incidents(),
                            "events": list(state.events), "stats": state.stats()})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await ws_mgr.disconnect(ws)


if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets") if (STATIC_DIR / "assets").exists() else None

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")
