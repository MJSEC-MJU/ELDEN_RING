import json

from src.manifest_builder import build_image_patch_manifests
from src.models import Phase3Result, RiskClass, ValidationStatus
from src.phase_contracts import Phase2AnalysisSummary, Phase2Result, Phase3PromoteEnvelope
from src.risk_classifier import RiskClassifier


def _sample_phase2() -> Phase2Result:
    return Phase2Result(
        context_id="ctx-evt-falco-1",
        event_id="evt-falco-1",
        patch_id="pth-abc",
        cwe_id="CWE-89",
        target_file="app/routes.py",
        target_function="login",
        patch_file="patches/pth-abc.diff",
        candidate_image="ghcr.io/mjsec-mju/elden-target-app:sha-abc",
        build_log=None,
        analysis_summary=Phase2AnalysisSummary(
            root_cause="string concat in SQL query", fix_strategy="use parameterized query"
        ),
        change_summary={"files": 1, "lines_changed": 5},
        patch_status="READY_FOR_VALIDATION",
    )


def test_envelope_roundtrip_via_redis_like_json():
    envelope = Phase3PromoteEnvelope(
        phase2=_sample_phase2(),
        exploit="PASSED", regression="PASSED", slo="PASSED",
        severity="HIGH",
    )
    wire = json.loads(envelope.model_dump_json())
    result = Phase3Result.parse(wire)

    assert isinstance(result, Phase3Result)
    assert result.incident_id == "evt-falco-1"
    assert result.event_id == "evt-falco-1"
    assert result.candidate_image == "ghcr.io/mjsec-mju/elden-target-app:sha-abc"
    assert result.patch_id == "pth-abc"
    assert result.cwe_id == "CWE-89"
    assert result.target_file == "app/routes.py"
    assert result.target_function == "login"
    assert result.all_passed is True


def test_legacy_payload_still_parses():
    wire = {
        "incident_id": "inc-legacy-1",
        "candidate_image": "img:1",
        "exploit": "PASSED", "regression": "PASSED", "slo": "PASSED",
        "manifests": [{"kind": "NetworkPolicy", "metadata": {"name": "np"}}],
    }
    result = Phase3Result.parse(wire)
    assert result.incident_id == "inc-legacy-1"
    assert result.event_id is None
    assert len(result.manifests) == 1


def test_failed_validation_parses_but_is_not_all_passed():
    envelope = Phase3PromoteEnvelope(
        phase2=_sample_phase2(),
        exploit="FAILED", regression="PASSED", slo="PASSED",
    )
    wire = json.loads(envelope.model_dump_json())
    result = Phase3Result.parse(wire)
    assert result.exploit == ValidationStatus.FAILED
    assert result.all_passed is False


def test_manifest_builder_creates_image_patch_rollout():
    envelope = Phase3PromoteEnvelope(
        phase2=_sample_phase2(),
        exploit="PASSED", regression="PASSED", slo="PASSED",
    )
    result = Phase3Result.parse(json.loads(envelope.model_dump_json()))
    manifests = build_image_patch_manifests(result)
    assert len(manifests) == 1
    m = manifests[0]
    assert m["kind"] == "Rollout"
    assert m["metadata"]["namespace"] == "elden-canary"
    ann = m["metadata"]["annotations"]
    assert ann["elden-ring/change-kind"] == "image"
    assert ann["elden-ring/cwe"] == "CWE-89"
    assert ann["elden-ring/patch-id"] == "pth-abc"
    assert ann["elden-ring/target-file"] == "app/routes.py"
    img = m["spec"]["template"]["spec"]["containers"][0]["image"]
    assert img == "ghcr.io/mjsec-mju/elden-target-app:sha-abc"


def test_auto_generated_rollout_classifies_high():
    envelope = Phase3PromoteEnvelope(
        phase2=_sample_phase2(),
        exploit="PASSED", regression="PASSED", slo="PASSED",
    )
    result = Phase3Result.parse(json.loads(envelope.model_dump_json()))
    manifests = build_image_patch_manifests(result)
    assert RiskClassifier().classify(manifests) == RiskClass.HIGH
