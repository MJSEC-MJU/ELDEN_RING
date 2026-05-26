"""Unit tests for the CWE E2E timing aggregator.

External calls (Loki / Prometheus) are *not* exercised here — those are
thin urllib wrappers. We test the pure aggregation logic against
hand-crafted ``TraceTimeline`` rows so a regression in mean/median or
the Markdown table is caught in CI without any networked service.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cwe_e2e_timings import (  # noqa: E402
    CWE_BASELINE,
    TraceTimeline,
    aggregate,
    render_csv,
    render_json,
    render_markdown,
)


def _tl(trace: str, cwe: str, detected: float, patched: float,
        promoted: float) -> TraceTimeline:
    return TraceTimeline(trace_id=trace, cwe_id=cwe,
                         detected=detected, patched=patched, promoted=promoted)


class TestAggregation:
    def test_complete_trace_total_seconds(self):
        tl = _tl("a", "CWE-89", 0.0, 5.0, 11.2)
        assert tl.complete() is True
        assert tl.total_seconds() == 11.2

    def test_incomplete_trace_drops(self):
        tl = TraceTimeline(trace_id="x", cwe_id="CWE-89", detected=0.0)
        stats = aggregate([tl])
        assert stats["CWE-89"].samples == []

    def test_mean_matches_inputs(self):
        rows = [_tl(f"t{i}", "CWE-89", 0.0, 1.0, t) for i, t in enumerate([10, 11, 12])]
        stats = aggregate(rows)
        # mean(10, 11, 12) = 11.0
        assert abs(stats["CWE-89"].mean() - 11.0) < 1e-9
        assert stats["CWE-89"].median() == 11.0

    def test_all_baseline_cwes_present_even_without_samples(self):
        """The presentation table needs every CWE row even when zero samples."""
        stats = aggregate([])
        for cwe in CWE_BASELINE:
            assert cwe in stats, f"{cwe} missing from aggregated stats"
            assert stats[cwe].samples == []
            assert stats[cwe].target_seconds == CWE_BASELINE[cwe][1]

    def test_unknown_cwe_bucketed_separately(self):
        rows = [_tl("u1", "CWE-XXX", 0.0, 1.0, 9.0)]
        stats = aggregate(rows)
        assert "CWE-XXX" in stats
        assert stats["CWE-XXX"].samples == [9.0]


class TestRendering:
    def test_markdown_table_lists_every_baseline_cwe(self):
        stats = aggregate([
            _tl("a", "CWE-89", 0.0, 5.0, 11.2),
            _tl("b", "CWE-918", 0.0, 5.0, 14.8),
        ])
        md = render_markdown(stats, "loki(test)")
        for cwe in CWE_BASELINE:
            assert cwe in md, f"Markdown table missing {cwe}"
        # Sample count for CWE-89 must reflect the single trace we fed in.
        assert "| CWE-89 | SQL Injection | 1 |" in md

    def test_markdown_delta_signed(self):
        # 13.10s baseline for Command Injection vs 14.10s measured → +1.00 delta.
        stats = aggregate([_tl("a", "CWE-78", 0.0, 5.0, 14.10)])
        md = render_markdown(stats, "loki(test)")
        assert "+1.00" in md

    def test_csv_header(self):
        stats = aggregate([])
        out = render_csv(stats)
        assert out.splitlines()[0] == (
            "cwe_id,name,samples,mean_s,median_s,stdev_s,target_s,delta_s,note"
        )

    def test_json_is_valid(self):
        stats = aggregate([_tl("a", "CWE-89", 0.0, 5.0, 11.0)])
        parsed = json.loads(render_json(stats))
        assert parsed["CWE-89"]["samples"] == 1
        assert parsed["CWE-89"]["target_seconds"] == 11.2


class TestEarliestTimestampWins:
    """If multiple log lines arrive for the same phase, the earliest one
    must be kept — duplicate lines must not inflate the elapsed."""

    def test_re_apply_keeps_earliest(self):
        tl = TraceTimeline(trace_id="t", cwe_id="CWE-89")
        # Simulate the merge logic from fetch_from_loki / fetch_from_prometheus.
        for stage, ts in [("detected", 100.0), ("detected", 50.0),
                          ("patched", 70.0), ("promoted", 120.0)]:
            current = getattr(tl, stage)
            if current is None or ts < current:
                setattr(tl, stage, ts)
        assert tl.detected == 50.0
        assert tl.patched == 70.0
        assert tl.promoted == 120.0
        assert tl.total_seconds() == 70.0
