from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from redis import Redis


REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
PROMOTE_CHANNEL = os.environ.get("PROMOTE_CHANNEL", "elden:phase4:promote")
DEPLOYED_CHANNEL = os.environ.get("DEPLOYED_CHANNEL", "elden:phase4:deployed")
ROLLBACK_CHANNEL = os.environ.get("ROLLBACK_CHANNEL", "elden:demo:rollback")
COMPOSE_FILE = os.environ.get("COMPOSE_FILE", "/repo/docker-compose.real.yml")
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "elden_real")
REPO_ROOT = Path(os.environ.get("REPO_ROOT", "/repo"))
TARGET_URL = os.environ.get("TARGET_URL", "http://target-app:5000")


def request_json(
    url: str,
    *,
    data: dict[str, str] | None = None,
    timeout: int = 5,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    body = None
    request_headers = dict(headers or {})
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=request_headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return exc.code, payload


def wait_ready() -> None:
    deadline = time.time() + 60
    last: Exception | None = None
    while time.time() < deadline:
        try:
            status, payload = request_json(f"{TARGET_URL}/readyz", timeout=2)
            if status == 200 and payload.get("status") == "ready":
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(1)
    raise RuntimeError(f"target-app did not become ready: {last}")


def deploy_target(*, build: bool = False) -> str:
    cmd = [
        "docker",
        "compose",
        "-p",
        COMPOSE_PROJECT,
        "-f",
        COMPOSE_FILE,
        "up",
        "-d",
        "--no-deps",
    ]
    if build:
        cmd.append("--build")
    cmd.append("target-app")
    completed = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout).strip())
    return (completed.stdout + completed.stderr).strip()


def reset_live_workspace() -> str:
    completed = subprocess.run(
        ["python3", "scripts/real_e2e/prepare_workspace.py", "--reset"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout).strip())
    return (completed.stdout + completed.stderr).strip()


def verify_sqli_fixed() -> dict[str, Any]:
    probe_headers = {"X-ELDEN-Probe": "deploy-agent-post-deploy"}
    valid_status, valid_body = request_json(
        f"{TARGET_URL}/api/login",
        data={"username": "demo", "password": "demo1234"},
        headers=probe_headers,
    )
    attack_status, attack_body = request_json(
        f"{TARGET_URL}/api/login",
        data={"username": "admin' OR 1=1 -- ", "password": "irrelevant"},
        headers=probe_headers,
    )
    valid_ok = valid_status == 200 and valid_body.get("status") == "success"
    attack_blocked = not (attack_status == 200 and attack_body.get("status") == "success")
    return {
        "valid_login": "passed" if valid_ok else "failed",
        "sqli_replay": "blocked" if attack_blocked else "still_vulnerable",
        "valid_status": valid_status,
        "attack_status": attack_status,
        "attack_body": attack_body,
    }


def verify_vulnerable_baseline() -> dict[str, Any]:
    probe_headers = {"X-ELDEN-Probe": "deploy-agent-rollback"}
    valid_status, valid_body = request_json(
        f"{TARGET_URL}/api/login",
        data={"username": "demo", "password": "demo1234"},
        headers=probe_headers,
    )
    attack_status, attack_body = request_json(
        f"{TARGET_URL}/api/login",
        data={"username": "admin' OR 1=1 -- ", "password": "irrelevant"},
        headers=probe_headers,
    )
    valid_ok = valid_status == 200 and valid_body.get("status") == "success"
    attack_succeeds = attack_status == 200 and attack_body.get("status") == "success"
    return {
        "valid_login": "passed" if valid_ok else "failed",
        "sqli_replay": "vulnerable" if attack_succeeds else "blocked",
        "valid_status": valid_status,
        "attack_status": attack_status,
        "attack_body": attack_body,
    }


def handle_promote(client: Redis, payload: dict[str, Any]) -> None:
    phase2 = payload.get("phase2") or {}
    incident_id = phase2.get("event_id") or payload.get("incident_id") or "unknown"
    result: dict[str, Any] = {
        "incident_id": incident_id,
        "event_id": incident_id,
        "candidate_image": phase2.get("candidate_image"),
        "deployment_ref": COMPOSE_PROJECT,
    }
    try:
        if any(payload.get(key) != "PASSED" for key in ("exploit", "regression", "slo")):
            raise RuntimeError("phase3 checks were not all PASSED")
        result["compose_output"] = deploy_target()
        wait_ready()
        checks = verify_sqli_fixed()
        result["checks"] = checks
        if checks["valid_login"] != "passed" or checks["sqli_replay"] != "blocked":
            raise RuntimeError(f"post-deploy verification failed: {checks}")
        result["status"] = "success"
    except Exception as exc:  # noqa: BLE001
        result["status"] = "failed"
        result["error"] = str(exc)
    client.publish(DEPLOYED_CHANNEL, json.dumps(result, ensure_ascii=False))
    print(json.dumps(result, ensure_ascii=False), flush=True)


def handle_rollback(client: Redis, payload: dict[str, Any]) -> None:
    request_id = payload.get("request_id") or f"rollback-{int(time.time())}"
    result: dict[str, Any] = {
        "incident_id": request_id,
        "event_id": request_id,
        "deployment_ref": COMPOSE_PROJECT,
        "action": "rollback_to_vulnerable",
    }
    try:
        result["workspace_output"] = reset_live_workspace()
        result["compose_output"] = deploy_target(build=True)
        wait_ready()
        checks = verify_vulnerable_baseline()
        result["checks"] = checks
        if checks["valid_login"] != "passed" or checks["sqli_replay"] != "vulnerable":
            raise RuntimeError(f"rollback verification failed: {checks}")
        result["status"] = "success"
    except Exception as exc:  # noqa: BLE001
        result["status"] = "failed"
        result["error"] = str(exc)
    client.publish(DEPLOYED_CHANNEL, json.dumps(result, ensure_ascii=False))
    print(json.dumps(result, ensure_ascii=False), flush=True)


def main() -> int:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    pubsub = client.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(PROMOTE_CHANNEL, ROLLBACK_CHANNEL)
    print(f"deploy-agent subscribed to {PROMOTE_CHANNEL}, {ROLLBACK_CHANNEL}", flush=True)
    for message in pubsub.listen():
        payload = json.loads(message["data"])
        if message["channel"] == ROLLBACK_CHANNEL:
            handle_rollback(client, payload)
        else:
            handle_promote(client, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
