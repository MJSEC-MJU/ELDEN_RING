from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def request_json_or_text(
    base_url: str,
    method: str,
    path: str,
    *,
    data: dict[str, str] | None = None,
    probe: bool = True,
    timeout: int = 10,
) -> dict[str, Any]:
    body = None
    headers = {}
    if probe:
        headers["X-ELDEN-Probe"] = "metrics-probe"
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = exc.code
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        return {
            "status": 0,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "body": {"error": str(exc)},
        }
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw
    return {"status": status, "elapsed_ms": elapsed_ms, "body": parsed}


def success_rate(values: list[bool]) -> float:
    return round(sum(values) / len(values) * 100, 2) if values else 0.0


def latency_summary(samples: list[dict[str, Any]]) -> dict[str, float | int]:
    latencies = [float(item["elapsed_ms"]) for item in samples]
    if not latencies:
        return {"count": 0, "avg_ms": 0.0, "p95_ms": 0.0}
    sorted_latencies = sorted(latencies)
    p95_idx = min(len(sorted_latencies) - 1, int(round(len(sorted_latencies) * 0.95)) - 1)
    return {
        "count": len(latencies),
        "avg_ms": round(statistics.mean(latencies), 2),
        "p95_ms": round(sorted_latencies[p95_idx], 2),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect live ELDEN RING demo metrics.")
    parser.add_argument("--base-url", default="http://34.136.94.175", help="Target site base URL")
    parser.add_argument("--monitor-url", default="http://34.136.94.175:8080", help="Pipeline monitor base URL")
    parser.add_argument("--trials", type=int, default=20, help="Number of repeated login/replay trials")
    parser.add_argument("--timeout", type=int, default=4, help="Per-request timeout for public target probes")
    args = parser.parse_args()

    valid_login_samples: list[dict[str, Any]] = []
    sqli_replay_samples: list[dict[str, Any]] = []
    for _ in range(args.trials):
        valid_login_samples.append(
            request_json_or_text(
                args.base_url,
                "POST",
                "/api/login",
                data={"username": "demo", "password": "demo1234"},
                timeout=args.timeout,
            )
        )
        sqli_replay_samples.append(
            request_json_or_text(
                args.base_url,
                "POST",
                "/api/login",
                data={"username": "admin' OR 1=1 -- ", "password": "irrelevant"},
                timeout=args.timeout,
            )
        )

    xss_probe = request_json_or_text(
        args.base_url,
        "GET",
        "/api/search?" + urllib.parse.urlencode({"q": "<script>alert(1)</script>"}),
        timeout=args.timeout,
    )
    path_probe = request_json_or_text(
        args.base_url,
        "GET",
        "/api/file?" + urllib.parse.urlencode({"name": "../../../etc/passwd"}),
        timeout=args.timeout,
    )
    monitor_status_samples = [
        request_json_or_text(args.monitor_url, "GET", "/api/target/status", probe=False, timeout=args.timeout)
        for _ in range(args.trials)
    ]

    valid_ok = [
        item["status"] == 200
        and isinstance(item["body"], dict)
        and item["body"].get("status") == "success"
        for item in valid_login_samples
    ]
    sqli_blocked = [
        item["status"] in {400, 401, 403, 404}
        and not (isinstance(item["body"], dict) and item["body"].get("status") == "success")
        for item in sqli_replay_samples
    ]
    sqli_not_exploited = [
        not (item["status"] == 200 and isinstance(item["body"], dict) and item["body"].get("status") == "success")
        for item in sqli_replay_samples
    ]
    monitor_internal_blocked = []
    for item in monitor_status_samples:
        body = item["body"] if isinstance(item["body"], dict) else {}
        replay = body.get("sqli_replay") if isinstance(body.get("sqli_replay"), dict) else {}
        replay_body = replay.get("body") if isinstance(replay.get("body"), dict) else {}
        monitor_internal_blocked.append(
            body.get("state") == "patched"
            and replay.get("status_code") in {400, 401, 403, 404}
            and replay_body.get("status") != "success"
        )
    site_success = all(valid_ok) and all(monitor_internal_blocked) and all(sqli_not_exploited)
    xss_body = xss_probe["body"] if isinstance(xss_probe["body"], str) else json.dumps(xss_probe["body"])
    path_blocked = path_probe["status"] in {400, 401, 403, 404}
    xss_escaped = "<script>alert(1)</script>" not in xss_body

    output = {
        "base_url": args.base_url,
        "monitor_url": args.monitor_url,
        "target_site_count": 1,
        "scenario_count": 4,
        "repeated_trials": args.trials,
        "site_success_count": 1 if site_success else 0,
        "site_success_rate": success_rate([site_success]),
        "scenarios": {
            "valid_login_regression": {
                "passed": all(valid_ok),
                "success_rate": success_rate(valid_ok),
                "latency": latency_summary(valid_login_samples),
            },
            "sqli_replay_block": {
                "passed": all(sqli_blocked),
                "success_rate": success_rate(sqli_blocked),
                "latency": latency_summary(sqli_replay_samples),
                "observed_status_codes": sorted({item["status"] for item in sqli_replay_samples}),
            },
            "sqli_replay_not_exploited_public_url": {
                "passed": all(sqli_not_exploited),
                "success_rate": success_rate(sqli_not_exploited),
                "timeout_or_error_count": sum(1 for item in sqli_replay_samples if item["status"] == 0),
                "note": "Public URL probes measure whether the exploit succeeds. Timeout/error is not counted as HTTP application blocking.",
            },
            "sqli_replay_block_internal_monitor": {
                "passed": all(monitor_internal_blocked),
                "success_rate": success_rate(monitor_internal_blocked),
                "latency": latency_summary(monitor_status_samples),
                "note": "Monitor checks target-app from inside the compose network and confirms patched HTTP replay behavior.",
            },
            "xss_probe_current_state": {
                "passed": xss_escaped,
                "status": xss_probe["status"],
                "note": "Probe header prevents this check from creating pipeline events.",
            },
            "path_traversal_probe_current_state": {
                "passed": path_blocked,
                "status": path_probe["status"],
                "note": "Probe header prevents this check from creating pipeline events.",
            },
        },
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
