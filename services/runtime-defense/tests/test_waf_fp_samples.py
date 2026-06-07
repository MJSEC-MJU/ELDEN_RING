"""Smoke tests for the CRS-942 FP sample corpus.

The corpus lives at ``scripts/loadtest/payloads/fp-samples/942_false_positives.json``
and is the regression set for the upcoming 942-family rule tuning
(see ``docs/phase1/waf-tuning-plan.md``).

These tests don't yet *exercise* the tuned rules (those don't exist
yet) — they just make sure the corpus file stays well-formed and that
every sample is marked ``expected_to_be: allowed`` so a future tuning
PR can't accidentally flip the expectation.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
FP_CORPUS = REPO_ROOT / "scripts" / "loadtest" / "payloads" / "fp-samples" / "942_false_positives.json"


def test_corpus_file_exists():
    assert FP_CORPUS.is_file(), f"FP corpus missing: {FP_CORPUS}"


def test_corpus_is_valid_json():
    json.loads(FP_CORPUS.read_text(encoding="utf-8"))


def test_corpus_has_samples_and_schema_marker():
    data = json.loads(FP_CORPUS.read_text(encoding="utf-8"))
    assert data.get("schema") == "elden-ring/phase1/waf-fp/v1"
    assert isinstance(data.get("samples"), list) and len(data["samples"]) >= 5


def test_every_sample_expects_allowed():
    """A sample tagged anything but 'allowed' would invert the tuning intent."""
    data = json.loads(FP_CORPUS.read_text(encoding="utf-8"))
    bad = [s["id"] for s in data["samples"] if s.get("expected_to_be") != "allowed"]
    assert not bad, f"Samples not marked allowed: {bad}"


def test_every_sample_lists_at_least_one_942_rule():
    """Confirms every entry actually hits a 942xxx rule — the whole point."""
    data = json.loads(FP_CORPUS.read_text(encoding="utf-8"))
    mismatched = []
    for s in data["samples"]:
        hits = s.get("modsec_rule_hits", [])
        if not hits or not all(str(h).startswith("942") for h in hits):
            mismatched.append((s.get("id"), hits))
    assert not mismatched, f"Samples without a 942xxx hit: {mismatched}"
