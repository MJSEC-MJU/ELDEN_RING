from __future__ import annotations

import asyncio
import difflib
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from fastapi import Body

from .llm_oauth import (
    LlmOAuthError,
    cancel_all_running_sessions,
    cancel_login_session,
    get_login_session,
    llm_status,
    run_patch_smoke,
    start_login,
    submit_login_code,
)
from .redis_subscriber import RedisSubscriber
from .state import PipelineState
from .ws_manager import WSManager


logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

REDIS_URL = os.environ.get("MONITOR_REDIS_URL", "redis://redis-master.elden-monitoring:6379/0")
GOV_URL = os.environ.get("MONITOR_GOVERNANCE_URL", "http://governance-controller.elden-governance:8080")
PHASE1_URL = os.environ.get("MONITOR_PHASE1_URL", "http://runtime-defense.elden-production:8080")
STATIC_DIR = Path(__file__).parent / "static"

state = PipelineState()
ws_mgr = WSManager()
app = FastAPI(title="ELDEN RING — Pipeline Monitor")

# Latest "real" LLM smoke call telemetry; surfaced via /api/llm/telemetry and WS events.
# This is what proves to the dashboard viewer that the codex/claude CLI was actually invoked.
LLM_TELEMETRY: dict[str, Any] = {
    "status": "idle",  # idle | running | success | failure
    "provider": None,
    "started_at": None,
    "finished_at": None,
    "duration_ms": None,
    "incident_id": None,
    "patch_id": None,
    "security_fix": None,
    "patch_preview": None,
    "error": None,
}
_LLM_TELEMETRY_LOCK = asyncio.Lock()


async def _set_llm_telemetry(**fields: Any) -> dict[str, Any]:
    async with _LLM_TELEMETRY_LOCK:
        LLM_TELEMETRY.update(fields)
        snapshot = dict(LLM_TELEMETRY)
    await ws_mgr.broadcast({"type": "llm_telemetry", "telemetry": snapshot})
    return snapshot


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
    # Belt-and-suspenders: previous pod generations may have left a stuck
    # `claude auth login` subprocess. With our supervisor (uvicorn) restarted
    # the in-memory session map is empty, but we still call this to mark any
    # leaked tracker entries as cancelled and free their stdin pipes.
    leaked = cancel_all_running_sessions()
    if leaked:
        logging.getLogger(__name__).info("Cancelled %d orphan login session(s) at startup", leaked)
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


@app.get("/api/llm/status")
async def get_llm_status() -> JSONResponse:
    return JSONResponse(llm_status())


@app.get("/api/llm/telemetry")
async def get_llm_telemetry() -> JSONResponse:
    return JSONResponse(LLM_TELEMETRY)


@app.post("/api/llm/login")
async def start_llm_login(provider: str = "codex") -> JSONResponse:
    try:
        return JSONResponse(start_login(provider))
    except LlmOAuthError as exc:
        return JSONResponse({"status": "error", "error": str(exc), "provider": provider}, status_code=400)


@app.get("/api/llm/login/{session_id}")
async def poll_llm_login(session_id: str) -> JSONResponse:
    try:
        return JSONResponse(get_login_session(session_id))
    except LlmOAuthError as exc:
        return JSONResponse({"status": "error", "error": str(exc), "session_id": session_id}, status_code=404)


@app.post("/api/llm/login/{session_id}/code")
async def submit_llm_login_code(session_id: str, body: dict = Body(...)) -> JSONResponse:
    try:
        code = (body or {}).get("code", "")
        return JSONResponse(submit_login_code(session_id, code))
    except LlmOAuthError as exc:
        return JSONResponse({"status": "error", "error": str(exc), "session_id": session_id}, status_code=400)


@app.post("/api/llm/login/{session_id}/cancel")
async def cancel_llm_login(session_id: str) -> JSONResponse:
    try:
        return JSONResponse(cancel_login_session(session_id))
    except LlmOAuthError as exc:
        return JSONResponse({"status": "error", "error": str(exc), "session_id": session_id}, status_code=404)


@app.post("/api/llm/simulate")
async def simulate_llm_secure_coding(provider: str = "codex") -> JSONResponse:
    started = time.time()
    await _set_llm_telemetry(
        status="running",
        provider=provider,
        started_at=started,
        finished_at=None,
        duration_ms=None,
        incident_id=None,
        patch_id=None,
        security_fix=None,
        patch_preview=None,
        error=None,
    )
    try:
        smoke = await asyncio.to_thread(run_patch_smoke, provider)
        finished = time.time()
        duration_ms = int((finished - started) * 1000)
        context, phase2, phase4 = _build_llm_simulation_payload(smoke, duration_ms=duration_ms)
        await _set_llm_telemetry(
            status="success",
            provider=smoke["provider"],
            finished_at=finished,
            duration_ms=duration_ms,
            incident_id=context["event_id"],
            patch_id=phase2["patch_id"],
            security_fix=(smoke["change_summary"] or {}).get("security_fix"),
            patch_preview=(smoke.get("patched_snippet") or "")[:400],
            error=None,
        )
        await _on_message("elden:phase2:context", context)
        await asyncio.sleep(0.35)
        await _on_message("elden:phase3:validate", phase2)
        await asyncio.sleep(0.35)
        await _on_message("elden:phase4:promote", phase4)
        return JSONResponse(
            {
                "status": "simulated",
                "incident_id": context["event_id"],
                "provider": smoke["provider"],
                "patch_id": phase2["patch_id"],
                "security_fix": smoke["change_summary"].get("security_fix"),
                "patched_snippet": smoke["patched_snippet"],
                "duration_ms": duration_ms,
                "llm_real": True,
            }
        )
    except LlmOAuthError as exc:
        await _set_llm_telemetry(
            status="failure",
            finished_at=time.time(),
            duration_ms=int((time.time() - started) * 1000),
            error=str(exc),
        )
        return JSONResponse({"status": "error", "error": str(exc), "provider": provider}, status_code=400)


@app.post("/api/inject")
async def inject_attack(scenario: str = "sqli") -> JSONResponse:
    presets = {
        "sqli": {
            "attack_category": "SQL Injection",
            "target_endpoint": {"method": "POST", "path": "/api/login"},
            "payload_sample": "admin' OR 1=1 --",
            "source_ip": "10.0.0.99",
            "severity": "HIGH",
        },
        "xss": {
            "attack_category": "Reflected XSS",
            "target_endpoint": {"method": "GET", "path": "/api/search"},
            "payload_sample": "<script>alert(1)</script>",
            "source_ip": "192.0.2.42",
            "severity": "MEDIUM",
        },
        "path": {
            "attack_category": "Path Traversal",
            "target_endpoint": {"method": "GET", "path": "/api/file"},
            "payload_sample": "../../../etc/passwd",
            "source_ip": "203.0.113.55",
            "severity": "HIGH",
        },
    }
    body = presets.get(scenario, presets["sqli"])
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{PHASE1_URL}/api/v1/events/manual", json=body)
            return JSONResponse({"status": "sent", "phase1_response": r.json(), "scenario": scenario})
    except Exception as e:
        return JSONResponse({"status": "error", "error": str(e), "scenario": scenario}, status_code=502)


def _build_llm_simulation_payload(smoke: dict, *, duration_ms: int | None = None) -> tuple[dict, dict, dict]:
    event_id = f"evt-llm-{uuid.uuid4().hex[:8]}"
    context_id = f"ctx-{event_id}"
    patch_id = f"patch-{uuid.uuid4().hex[:8]}"
    original = "\n".join(
        [
            "def authenticate(username, password, db):",
            "    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
            "    result = db.execute(query)",
            "    return result",
            "",
        ]
    )
    patched = smoke["patched_snippet"]
    if not patched.endswith("\n"):
        patched += "\n"
    unified_diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile="a/routes/auth.py",
            tofile="b/routes/auth.py",
        )
    )
    context = {
        "context_id": context_id,
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_info": {
            "category": "SQL Injection",
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "owasp_category": "A03:2021",
            "payload_sample": "admin' OR 1=1 --",
            "source_ip": "127.0.0.1",
            "blocked": False,
        },
        "target": {
            "endpoint": {"method": "POST", "path": "/api/login"},
            "source_mapping": {
                "file": "routes/auth.py",
                "function": "authenticate",
                "line_start": 1,
                "line_end": 4,
            },
        },
        "metadata": {
            "severity": "HIGH",
            "pipeline_version": "llm-dashboard-smoke",
            "defense_action_taken": "manual-dashboard-llm-smoke",
            "requires_patch": True,
            "simulated": True,
            "llm_real": True,
        },
    }
    phase2 = {
        "job_id": f"sc-{uuid.uuid4().hex[:8]}",
        "context_id": context_id,
        "event_id": event_id,
        "patch_id": patch_id,
        "cwe_id": "CWE-89",
        "target_file": "routes/auth.py",
        "target_function": "authenticate",
        "patch_file": f"artifacts/patches/{patch_id}.diff",
        "candidate_image": f"ghcr.io/mjsec-mju/elden-target-app:candidate-{event_id}-{patch_id}",
        "severity": "HIGH",
        "build_log": "dashboard LLM smoke: real LLM patch generation, build/push step simulated",
        "analysis_summary": {
            "root_cause": "user-controlled values were interpolated directly into SQL",
            "fix_strategy": smoke["change_summary"].get("security_fix") or "use parameterized SQL binding",
        },
        "change_summary": {
            "files_changed": 1,
            "functions_changed": ["authenticate"],
            "security_fix": smoke["change_summary"].get("security_fix"),
            "llm_provider": smoke["provider"],
            "patched_snippet": smoke["patched_snippet"],
            "unified_diff": unified_diff,
            "llm_real": True,
            "llm_duration_ms": duration_ms,
        },
        "patch_status": "READY_FOR_VALIDATION",
        "simulated": True,
        "llm_real": True,
    }
    phase4 = {
        "phase2": phase2,
        "exploit": "PASSED",
        "regression": "PASSED",
        "slo": "PASSED",
        "risk": "low",
        "branch": f"defense/inc-{event_id}",
    }
    return context, phase2, phase4


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws_mgr.connect(ws)
    try:
        await ws.send_json({"type": "snapshot", "incidents": state.snapshot_incidents(),
                            "events": list(state.events), "stats": state.stats(),
                            "llm_telemetry": dict(LLM_TELEMETRY)})
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
        # Avoid stale dashboard JS/HTML after rollouts — every load fetches fresh markup.
        return FileResponse(
            STATIC_DIR / "index.html",
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
        )
