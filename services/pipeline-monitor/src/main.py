from __future__ import annotations

import asyncio
import difflib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Body, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from redis import Redis

from .llm_oauth import (
    LlmOAuthError,
    cancel_all_running_sessions,
    cancel_login_session,
    get_login_session,
    llm_status,
    run_patch_smoke,
    run_validation_smoke,
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
TARGET_URL = os.environ.get("MONITOR_TARGET_URL", "http://target-app:5000")
ROLLBACK_CHANNEL = os.environ.get("MONITOR_ROLLBACK_CHANNEL", "elden:demo:rollback")
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


def _short_body(text: str, limit: int = 1200) -> str:
    return text if len(text) <= limit else f"{text[:limit]}..."


async def _target_get(path: str) -> dict[str, Any]:
    started = time.time()
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(f"{TARGET_URL}{path}")
    elapsed_ms = int((time.time() - started) * 1000)
    try:
        body: Any = r.json()
    except Exception:
        body = {"raw": _short_body(r.text)}
    return {"status_code": r.status_code, "elapsed_ms": elapsed_ms, "body": body}


async def _target_login(username: str, password: str, *, probe: bool = False) -> dict[str, Any]:
    started = time.time()
    headers = {"X-ELDEN-Probe": "target-status"} if probe else None
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(
            f"{TARGET_URL}/api/login",
            data={"username": username, "password": password},
            headers=headers,
        )
    elapsed_ms = int((time.time() - started) * 1000)
    try:
        body: Any = r.json()
    except Exception:
        body = {"raw": _short_body(r.text)}
    return {
        "status_code": r.status_code,
        "elapsed_ms": elapsed_ms,
        "body": body,
        "username": username,
    }


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


@app.get("/api/target/status")
async def get_target_status() -> JSONResponse:
    response: dict[str, Any] = {
        "target_url": TARGET_URL,
        "ready": None,
        "valid_login": None,
        "sqli_replay": None,
        "state": "unknown",
        "error": None,
    }
    try:
        response["ready"] = await _target_get("/readyz")
        response["valid_login"] = await _target_login("demo", "demo1234", probe=True)
        response["sqli_replay"] = await _target_login("admin' OR 1=1 -- ", "irrelevant", probe=True)

        replay = response["sqli_replay"] or {}
        body = replay.get("body") or {}
        vulnerable = replay.get("status_code") == 200 and body.get("status") == "success"
        if vulnerable:
            response["state"] = "vulnerable"
        elif replay.get("status_code") in {400, 401, 403}:
            response["state"] = "patched"
        else:
            response["state"] = "unknown"
    except Exception as exc:
        response["error"] = str(exc)
    return JSONResponse(response)


def _publish_rollback(request_id: str) -> None:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    client.publish(
        ROLLBACK_CHANNEL,
        json.dumps(
            {
                "request_id": request_id,
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "source": "pipeline-monitor",
            },
            ensure_ascii=False,
        ),
    )


@app.post("/api/rollback")
async def rollback_demo() -> JSONResponse:
    request_id = f"rollback-{uuid.uuid4().hex[:8]}"
    try:
        await asyncio.to_thread(_publish_rollback, request_id)
        state.clear()
        await ws_mgr.broadcast({
            "type": "snapshot",
            "incidents": state.snapshot_incidents(),
            "events": list(state.events),
            "stats": state.stats(),
            "llm_telemetry": dict(LLM_TELEMETRY),
        })
        return JSONResponse({
            "status": "sent",
            "request_id": request_id,
            "message": "rollback requested; target-app will be rebuilt from the vulnerable baseline",
        })
    except Exception as exc:
        return JSONResponse({"status": "error", "error": str(exc), "request_id": request_id}, status_code=502)


@app.post("/api/target/login")
async def post_target_login(body: dict = Body(...)) -> JSONResponse:
    username = str((body or {}).get("username", ""))
    password = str((body or {}).get("password", ""))
    try:
        result = await _target_login(username, password)
        return JSONResponse({"target_url": TARGET_URL, "result": result})
    except Exception as exc:
        return JSONResponse({"target_url": TARGET_URL, "error": str(exc)}, status_code=502)


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
        phase3_validation = await asyncio.to_thread(run_validation_smoke, provider, context, phase2)
        phase4.update(
            {
                "exploit": phase3_validation["exploit"],
                "regression": phase3_validation["regression"],
                "slo": phase3_validation["slo"],
                "risk": phase3_validation["risk"],
                "phase3_llm": phase3_validation,
            }
        )
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
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            if scenario == "xss":
                r = await client.get(f"{TARGET_URL}/api/search", params={"q": "<script>alert(1)</script>"})
            elif scenario == "path":
                r = await client.get(f"{TARGET_URL}/api/file", params={"name": "../../../etc/passwd"})
            else:
                r = await client.post(
                    f"{TARGET_URL}/api/login",
                    data={"username": "admin' OR 1=1 -- ", "password": "irrelevant"},
                )
            try:
                body: Any = r.json()
            except Exception:
                body = {"raw": _short_body(r.text)}
            return JSONResponse({
                "status": "sent",
                "scenario": scenario,
                "target_response": {"status_code": r.status_code, "body": body},
            })
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
