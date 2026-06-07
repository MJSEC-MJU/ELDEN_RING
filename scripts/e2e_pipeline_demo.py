"""Full ELDEN RING pipeline E2E demo (Phase 1 -> 2 -> 3 -> 4) over real Redis.

Phase 1/2/3 are simulated as async tasks. Phase 4 uses the REAL governance
modules (Phase3Result.parse, manifest_builder, risk_classifier).

Requires: redis container at localhost:6379.
"""
from __future__ import annotations

import asyncio
import io
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
elif hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "secure-coding" / "src"))
sys.path.insert(0, str(ROOT / "services" / "governance"))

import redis.asyncio as redis_async  # noqa: E402

from secure_coding_plane.schemas import (  # noqa: E402
    AnalysisSummary, RuntimeContextPackage, SecureCodingResult,
)
from src.manifest_builder import build_image_patch_manifests  # noqa: E402
from src.models import Phase3Result, RiskClass  # noqa: E402
from src.risk_classifier import RiskClassifier  # noqa: E402


REDIS_URL = "redis://localhost:6379/0"
CH_PHASE2_CONTEXT = "elden:phase2:context"
CH_PHASE3_VALIDATE = "elden:phase3:validate"
CH_PHASE4_PROMOTE = "elden:phase4:promote"


def banner(label: str) -> None:
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {'-' * 4} {label} {'-' * (50 - len(label))}")


# ---------- Phase 1: simulator ----------
async def phase1_publisher(client: redis_async.Redis) -> dict:
    banner("Phase 1 (Runtime Defense) -- simulating attack detection")
    incident_id = f"inc-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"
    ctx = RuntimeContextPackage(
        context_id=f"ctx-{incident_id}",
        event_id=incident_id,
        timestamp=datetime.now(timezone.utc),
        attack_info={
            "category": "SQL Injection",
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "owasp_category": "A03:2021",
            "payload_sample": "admin' OR 1=1--",
            "source_ip": "10.244.1.42",
            "blocked": False,
        },
        target={
            "endpoint": {"method": "POST", "path": "/api/login"},
            "source_mapping": {
                "file": "services/target-app/src/routes/login.py",
                "function": "authenticate",
                "line_start": 12, "line_end": 28,
            },
        },
        metadata={
            "severity": "HIGH",
            "pipeline_version": "1.0.0",
            "defense_action_taken": "rate-limit",
            "requires_patch": True,
        },
    )
    print(f"  detected: SQL injection on /api/login, severity=HIGH")
    print(f"  context_id={ctx.context_id}")
    print(f"  publishing to {CH_PHASE2_CONTEXT}")
    payload = json.loads(ctx.model_dump_json())
    await client.publish(CH_PHASE2_CONTEXT, json.dumps(payload))
    return payload


# ---------- Phase 2: simulator ----------
async def phase2_worker(client: redis_async.Redis, ready: asyncio.Event) -> None:
    pubsub = client.pubsub()
    await pubsub.subscribe(CH_PHASE2_CONTEXT)
    ready.set()
    async for msg in pubsub.listen():
        if msg.get("type") != "message":
            continue
        ctx = json.loads(msg["data"])
        banner("Phase 2 (Secure Coding) -- received context, simulating LLM patch")
        print(f"  consumed event_id={ctx['event_id']}")
        print("  steps: analysis -> strategy -> patching -> recheck -> apply -> build(simulate)")
        result = SecureCodingResult(
            job_id=f"sc-{uuid.uuid4().hex[:8]}",
            context_id=ctx["context_id"],
            event_id=ctx["event_id"],
            patch_id=f"pth-{uuid.uuid4().hex[:8]}",
            cwe_id=ctx["attack_info"]["cwe_id"],
            target_file=ctx["target"]["source_mapping"]["file"],
            target_function=ctx["target"]["source_mapping"]["function"],
            patch_file=f"patches/pth-{uuid.uuid4().hex[:8]}.diff",
            candidate_image=f"ghcr.io/mjsec-mju/elden-target-app:sha-{uuid.uuid4().hex[:8]}",
            severity="HIGH",
            analysis_summary=AnalysisSummary(
                root_cause="raw f-string concat in cursor.execute",
                fix_strategy="convert to parameterized query",
            ),
            change_summary={"files_changed": 1, "lines_added": 3, "lines_removed": 2},
            patch_status="READY_FOR_VALIDATION",
        )
        print(f"  produced candidate_image={result.candidate_image}")
        print(f"  publishing to {CH_PHASE3_VALIDATE}")
        await client.publish(CH_PHASE3_VALIDATE, result.model_dump_json())
        break
    await pubsub.unsubscribe()
    await pubsub.aclose()


# ---------- Phase 3: simulator ----------
async def phase3_worker(client: redis_async.Redis, ready: asyncio.Event) -> None:
    pubsub = client.pubsub()
    await pubsub.subscribe(CH_PHASE3_VALIDATE)
    ready.set()
    async for msg in pubsub.listen():
        if msg.get("type") != "message":
            continue
        p2 = json.loads(msg["data"])
        banner("Phase 3 (Recovery Assurance) -- simulating validation")
        print(f"  received SecureCodingResult patch_id={p2['patch_id']}")
        print("  running: exploit replay / regression / SLO check")
        envelope = {
            "phase2": p2,
            "exploit": "PASSED",
            "regression": "PASSED",
            "slo": "PASSED",
        }
        print("  results: exploit=PASSED regression=PASSED slo=PASSED -> eligible for promotion")
        print(f"  publishing to {CH_PHASE4_PROMOTE}")
        await client.publish(CH_PHASE4_PROMOTE, json.dumps(envelope))
        break
    await pubsub.unsubscribe()
    await pubsub.aclose()


# ---------- Phase 4: REAL governance code ----------
async def phase4_orchestrator(client: redis_async.Redis, ready: asyncio.Event) -> dict:
    pubsub = client.pubsub()
    await pubsub.subscribe(CH_PHASE4_PROMOTE)
    ready.set()
    async for msg in pubsub.listen():
        if msg.get("type") != "message":
            continue
        envelope = json.loads(msg["data"])
        banner("Phase 4 (Governance) -- envelope received [REAL CODE PATH]")
        result = Phase3Result.parse(envelope)
        print(f"  Phase3Result.parse() OK")
        print(f"    incident_id  = {result.incident_id}")
        print(f"    job_id       = {result.job_id}")
        print(f"    patch_id     = {result.patch_id}")
        print(f"    cwe_id       = {result.cwe_id}")
        print(f"    target       = {result.target_file}::{result.target_function}")
        print(f"    severity     = {result.severity}")
        print(f"    all_passed   = {result.all_passed}")

        manifests = build_image_patch_manifests(result)
        print(f"  manifest_builder -> {len(manifests)} Rollout manifest(s)")
        for m in manifests:
            print(f"    {m['kind']}/{m['metadata']['name']} ns={m['metadata']['namespace']}")
            img = m["spec"]["template"]["spec"]["containers"][0]["image"]
            print(f"    image -> {img}")

        risk = RiskClassifier().classify(manifests)
        print(f"  risk_classifier -> {risk.value.upper()}")

        ident = result.incident_id[4:] if result.incident_id.startswith("inc-") else result.incident_id
        branch = f"defense/inc-{ident}"
        print(f"  git_writer would open PR on branch '{branch}'")
        if risk == RiskClass.HIGH:
            print("  promotion_gate: HIGH risk -> Rollout pauses at 50%, awaits POST /approve")
        else:
            print(f"  promotion_gate: {risk.value} risk -> auto-resume canary")

        await pubsub.unsubscribe()
        await pubsub.aclose()
        return {"incident_id": result.incident_id, "branch": branch, "risk": risk.value}


async def main() -> int:
    print("=" * 70)
    print("  ELDEN RING - Full Pipeline E2E Demo")
    print("  Phase 1 -> 2 -> 3 -> 4 (real Redis, Phase 4 real code)")
    print("=" * 70)

    client = redis_async.from_url(REDIS_URL, decode_responses=True)
    try:
        await client.ping()
    except Exception as e:
        print(f"[FATAL] Redis ping failed: {e}")
        print("        Run: docker run -d --rm --name elden-redis -p 6379:6379 redis:7-alpine")
        return 1
    print(f"[OK] Redis connected at {REDIS_URL}")

    p2_ready = asyncio.Event()
    p3_ready = asyncio.Event()
    p4_ready = asyncio.Event()

    p4_task = asyncio.create_task(phase4_orchestrator(client, p4_ready))
    p3_task = asyncio.create_task(phase3_worker(client, p3_ready))
    p2_task = asyncio.create_task(phase2_worker(client, p2_ready))

    await asyncio.gather(p2_ready.wait(), p3_ready.wait(), p4_ready.wait())
    print("[OK] subscribers ready (Phase 2/3/4)")

    await phase1_publisher(client)

    p4_result = await asyncio.wait_for(p4_task, timeout=15)
    await asyncio.gather(p2_task, p3_task)

    banner("FINAL RESULT")
    print(f"  incident:  {p4_result['incident_id']}")
    print(f"  branch:    {p4_result['branch']}")
    print(f"  risk:      {p4_result['risk'].upper()}")
    print(f"  outcome:   defense PR opened, canary Rollout pauses for manual approval")
    print()
    print("All four phases successfully exchanged messages over Redis.")
    print("Phase 4 governance pipeline produced a defense-candidate.")

    await client.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
