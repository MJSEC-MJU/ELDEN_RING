from __future__ import annotations

from unittest.mock import patch

from src.state import PipelineState


def _context(event_id: str, cwe_id: str = "CWE-89") -> dict:
    return {
        "event_id": event_id,
        "attack_info": {
            "category": "SQL Injection",
            "cwe_id": cwe_id,
        },
        "metadata": {
            "severity": "HIGH",
        },
    }


def _phase2(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "patch_id": f"patch-{event_id}",
        "candidate_image": f"candidate:{event_id}",
    }


def _phase4(event_id: str) -> dict:
    return {
        "phase2": {
            "event_id": event_id,
        },
        "risk": "low",
        "branch": f"defense/{event_id}",
        "exploit": "PASSED",
        "regression": "PASSED",
        "slo": "PASSED",
    }


def test_stats_include_cwe_breakdown_duration_and_recent_incidents() -> None:
    state = PipelineState()

    with patch("src.state.time.time", side_effect=[100.0, 104.0, 111.0, 120.0, 124.0, 128.0]):
        state.push_event("elden:phase2:context", _context("evt-1"))
        state.push_event("elden:phase3:validate", _phase2("evt-1"))
        state.push_event("elden:phase4:promote", _phase4("evt-1"))
        state.push_event("elden:phase2:context", _context("evt-2"))
        state.push_event("elden:phase3:validate", _phase2("evt-2"))
        state.push_event("elden:phase4:promote", _phase4("evt-2"))

    stats = state.stats()

    assert stats["by_cwe"] == {"CWE-89": 2}
    assert stats["cwe_breakdown"]["CWE-89"]["count"] == 2
    assert stats["cwe_breakdown"]["CWE-89"]["avg_duration_seconds"] == 9.5
    assert [item["incident_id"] for item in stats["cwe_breakdown"]["CWE-89"]["recent_incidents"]] == [
        "evt-2",
        "evt-1",
    ]


def test_snapshot_incidents_exposes_duration_seconds() -> None:
    state = PipelineState()

    with patch("src.state.time.time", side_effect=[200.0, 207.25]):
        state.push_event("elden:phase2:context", _context("evt-1", cwe_id="CWE-79"))
        state.push_event("elden:phase3:validate", _phase2("evt-1"))

    [incident] = state.snapshot_incidents()

    assert incident["incident_id"] == "evt-1"
    assert incident["cwe_id"] == "CWE-79"
    assert incident["duration_seconds"] == 7.25
