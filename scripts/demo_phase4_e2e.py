"""End-to-end demo: Phase 2 SecureCodingResult -> Phase 4 governance pipeline.

In-process simulation. No Redis, no K8s, no GitHub. Proves that the data
contract holds and that each stage produces the expected output.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
elif hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "secure-coding" / "src"))
sys.path.insert(0, str(ROOT / "services" / "governance"))

from secure_coding_plane.schemas import AnalysisSummary, SecureCodingResult

from src.manifest_builder import build_image_patch_manifests
from src.models import Phase3Result, RiskClass, ValidationStatus
from src.risk_classifier import RiskClassifier


def section(label: str) -> None:
    print(f"\n{'=' * 6} {label} {'=' * (60 - len(label))}")


def main() -> int:
    section("Phase 1/2 - simulated incident + Phase 2 patch result")
    p2 = SecureCodingResult(
        job_id="sc-job-2026-04-13-001",
        context_id="ctx-evt-falco-001",
        event_id="inc-2026-04-13-001",
        patch_id="pth-7af3b2",
        cwe_id="CWE-89",
        target_file="services/target-app/src/routes/login.py",
        target_function="authenticate",
        patch_file="patches/pth-7af3b2.diff",
        candidate_image="ghcr.io/mjsec-mju/elden-target-app:sha-7af3b2c1",
        severity="HIGH",
        analysis_summary=AnalysisSummary(
            root_cause="raw string concatenation in SQL query (login flow)",
            fix_strategy="convert to parameterized cursor.execute call",
        ),
        change_summary={"files_changed": 1, "lines_added": 4, "lines_removed": 3},
        patch_status="READY_FOR_VALIDATION",
    )
    print(f"event_id      = {p2.event_id}")
    print(f"cwe_id        = {p2.cwe_id}")
    print(f"target        = {p2.target_file}::{p2.target_function}")
    print(f"candidate img = {p2.candidate_image}")
    print(f"severity      = {p2.severity}")

    section("Phase 3 - wrap Phase 2 result into promote envelope")
    envelope = {
        "phase2": json.loads(p2.model_dump_json()),
        "exploit": "PASSED",
        "regression": "PASSED",
        "slo": "PASSED",
    }
    print("envelope keys:", sorted(envelope.keys()))
    print("envelope.exploit/regression/slo all PASSED - eligible for promotion")

    section("Phase 4 - orchestrator parse")
    result = Phase3Result.parse(envelope)
    print(f"incident_id   = {result.incident_id}")
    print(f"event_id      = {result.event_id}")
    print(f"job_id        = {result.job_id}")
    print(f"patch_id      = {result.patch_id}")
    print(f"cwe_id        = {result.cwe_id}")
    print(f"severity      = {result.severity}  (carried from phase2)")
    print(f"all_passed    = {result.all_passed}")

    section("Phase 4 - manifest auto-build (Phase 3 omitted manifests)")
    manifests = build_image_patch_manifests(result)
    print(f"generated {len(manifests)} manifest(s):")
    for m in manifests:
        kind = m["kind"]
        ns = m["metadata"]["namespace"]
        name = m["metadata"]["name"]
        print(f"  - {kind}/{name} in {ns}")
        print(f"    annotations:")
        for k, v in m["metadata"]["annotations"].items():
            print(f"      {k}: {v}")
        img = m["spec"]["template"]["spec"]["containers"][0]["image"]
        print(f"    image: {img}")

    section("Phase 4 - risk classifier")
    risk = RiskClassifier().classify(manifests)
    print(f"classified risk = {risk.value.upper()}")
    if risk == RiskClass.HIGH:
        print("-> requires manual approval at the canary 50% step (manual pause)")
    elif risk == RiskClass.MEDIUM:
        print("-> auto-promote with extended canary window")
    else:
        print("-> auto-promote on the standard canary schedule")

    section("Phase 4 - what would happen next (real cluster)")
    print("1. git_writer: open PR against MJSEC-MJU/ELDEN_RING dev branch")
    ident = result.incident_id[4:] if result.incident_id.startswith("inc-") else result.incident_id
    print(f"   branch  = defense/inc-{ident}")
    print(f"   labels  = defense-candidate, risk/{risk.value}")
    print(f"   path    = kubernetes/environments/canary/incidents/{result.incident_id}/")
    print("2. ArgoCD ApplicationSet picks up the labeled PR -> sync to elden-canary")
    print("3. Kyverno admission webhook validates manifest -> PolicyReports")
    print("4. policy_gate aggregates reports; on PASS proceeds to C layer")
    print("5. Argo Rollouts canary steps: 10 -> analysis -> 30 -> analysis -> 50")
    if risk == RiskClass.HIGH:
        print("6. paused at 50% awaiting POST /incidents/{id}/approve")
    else:
        print("6. promotion_gate auto-resumes through to 100%")
    print("7. dev -> main merge triggers prod Application sync")
    print("8. rollback_watcher polls Prometheus; abort on SLO breach")

    section("Demo PR body (what git_writer would write)")
    summary_lines = [
        f"- exploit replay: **{result.exploit.value}**",
        f"- regression:    **{result.regression.value}**",
        f"- SLO:           **{result.slo.value}**",
        f"- candidate:     `{result.candidate_image}`",
        f"- CWE:           `{result.cwe_id}`",
        f"- patch id:      `{result.patch_id}`",
        f"- target:        `{result.target_file}::{result.target_function}`",
    ]
    print("\n".join(summary_lines))

    section("Result")
    assert result.all_passed
    assert risk == RiskClass.HIGH
    assert len(manifests) == 1
    assert manifests[0]["spec"]["template"]["spec"]["containers"][0]["image"] == p2.candidate_image
    print("ALL CHECKS PASS - Phase 2 -> Phase 4 contract works end-to-end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
