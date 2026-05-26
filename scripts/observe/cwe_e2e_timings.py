#!/usr/bin/env python3
"""Phase 1 Week 11 — CWE-wise end-to-end timing aggregator.

For every ``trace_id`` propagated through the 4-phase pipeline
(``Phase 1 detected → Phase 2 patched → Phase 4 prod-promoted``), this
script computes the per-stage and total elapsed seconds and groups them
by CWE. Two data sources are used:

  1. **Loki** (preferred). Each phase emits structured logs that include
     ``trace_id`` and a phase-marker (``phase1_detected``,
     ``phase2_patched``, ``phase4_promoted``). The script queries
     ``{job=~"elden-.*"} | json | trace_id != ""`` over the requested
     window and pairs the timestamps per trace.

  2. **Prometheus fallback**. When Loki is unavailable we fall back to
     the per-trace gauges that each phase exports:
       * Phase 1: ``runtime_defense_detected_at_unixseconds``
       * Phase 2: ``secure_coding_patched_at_unixseconds``
       * Phase 4: ``recovery_assurance_promoted_at_unixseconds``
     These carry ``trace_id`` + ``cwe_id`` labels and are sufficient for
     the demo-day numbers as long as Prometheus retention covers the
     measurement window.

Output:
  * Human-readable Markdown table (--format=md, default) suitable for
    the presentation deck performance section.
  * ``--format=json`` machine readable per-CWE / per-trace stats.
  * ``--format=csv`` flat rows for spreadsheet import.

The reference numbers shipped in ``CWE_BASELINE`` are the targets
agreed for the Week 11 review (SQLi 11.2s, XSS 12.4s, CmdInj 13.1s,
SSRF 14.8s incl. one retry, Deserialization 10.9s, Path Traversal
11.7s). They are printed alongside the measured value so deviations
are obvious at a glance.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional


# ── Targets (Week 11 review reference values) ─────────────────────────────

# CWE-ID → (display name, agreed target seconds, note shown in table)
CWE_BASELINE: dict[str, tuple[str, float, str]] = {
    "CWE-89":  ("SQL Injection",                11.2, ""),
    "CWE-79":  ("Cross-Site Scripting",         12.4, ""),
    "CWE-78":  ("Command Injection",            13.1, ""),
    "CWE-918": ("Server-Side Request Forgery",  14.8, "includes 1 retry"),
    "CWE-502": ("Insecure Deserialization",     10.9, ""),
    "CWE-22":  ("Path Traversal",               11.7, ""),
}


PHASE_MARKERS = {
    "phase1_detected":  "detected",
    "phase2_patched":   "patched",
    "phase4_promoted":  "promoted",
}

# Prometheus gauge names that mirror the Loki markers (fallback path).
PROM_GAUGES = {
    "detected": "runtime_defense_detected_at_unixseconds",
    "patched":  "secure_coding_patched_at_unixseconds",
    "promoted": "recovery_assurance_promoted_at_unixseconds",
}


# ── Trace timeline aggregation ────────────────────────────────────────────

@dataclass
class TraceTimeline:
    """Per-``trace_id`` collection of phase-marker timestamps."""
    trace_id: str
    cwe_id: str = "UNKNOWN"
    detected:  Optional[float] = None
    patched:   Optional[float] = None
    promoted:  Optional[float] = None

    def complete(self) -> bool:
        # Explicit None check — 0.0 is a valid unix timestamp in tests.
        return None not in (self.detected, self.patched, self.promoted)

    def total_seconds(self) -> Optional[float]:
        if not self.complete():
            return None
        return self.promoted - self.detected  # type: ignore[operator]

    def stages(self) -> dict[str, Optional[float]]:
        if not self.complete():
            return {"detect_to_patch": None, "patch_to_promote": None}
        return {
            "detect_to_patch":  self.patched   - self.detected,   # type: ignore[operator]
            "patch_to_promote": self.promoted  - self.patched,    # type: ignore[operator]
        }


@dataclass
class CWEStats:
    cwe_id: str
    name: str
    target_seconds: Optional[float]
    samples: list[float] = field(default_factory=list)
    note: str = ""

    def mean(self) -> Optional[float]:
        return statistics.mean(self.samples) if self.samples else None

    def median(self) -> Optional[float]:
        return statistics.median(self.samples) if self.samples else None

    def stdev(self) -> Optional[float]:
        return statistics.stdev(self.samples) if len(self.samples) > 1 else None


# ── HTTP helpers ──────────────────────────────────────────────────────────

def _http_get_json(url: str, params: dict | None = None,
                   timeout: float = 15.0) -> dict:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


# ── Loki source ───────────────────────────────────────────────────────────

def fetch_from_loki(base_url: str, window_seconds: int) -> dict[str, TraceTimeline]:
    """Pull phase-marker logs from Loki over the last ``window_seconds``.

    Loki query selects any log line that carries a non-empty ``trace_id``
    and one of the phase markers. We don't constrain ``{job=…}`` here so
    a single query covers all three phases.
    """
    end = int(_now()) * 1_000_000_000  # ns
    start = end - window_seconds * 1_000_000_000

    query = '{job=~"elden-.*"} | json | trace_id != "" | line_format "{{.trace_id}} {{.cwe_id}} {{.message}} {{.phase_marker}}"'

    resp = _http_get_json(f"{base_url.rstrip('/')}/loki/api/v1/query_range", {
        "query": query,
        "start": str(start),
        "end":   str(end),
        "limit": "5000",
    })

    timelines: dict[str, TraceTimeline] = {}
    for stream in resp.get("data", {}).get("result", []):
        for ts_ns, line in stream.get("values", []):
            ts_s = float(ts_ns) / 1e9
            # Loki line_format puts: "<trace_id> <cwe_id> <message> <phase_marker>"
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            trace_id, cwe_id, _msg, marker = parts[0], parts[1], parts[2], parts[-1]
            tl = timelines.setdefault(trace_id, TraceTimeline(trace_id=trace_id))
            if cwe_id and cwe_id != "UNKNOWN":
                tl.cwe_id = cwe_id
            stage = PHASE_MARKERS.get(marker)
            if not stage:
                continue
            # Earliest occurrence wins per stage — defends against repeated lines.
            current = getattr(tl, stage)
            if current is None or ts_s < current:
                setattr(tl, stage, ts_s)
    return timelines


# ── Prometheus source (fallback) ──────────────────────────────────────────

def fetch_from_prometheus(prom_url: str) -> dict[str, TraceTimeline]:
    """Fallback: read the per-trace timestamp gauges from Prometheus."""
    timelines: dict[str, TraceTimeline] = {}
    for stage, gauge in PROM_GAUGES.items():
        resp = _http_get_json(f"{prom_url.rstrip('/')}/api/v1/query",
                              {"query": gauge})
        for series in resp.get("data", {}).get("result", []):
            labels = series.get("metric", {})
            trace_id = labels.get("trace_id")
            cwe_id = labels.get("cwe_id", "UNKNOWN")
            if not trace_id:
                continue
            try:
                ts = float(series["value"][1])
            except (KeyError, IndexError, ValueError):
                continue
            tl = timelines.setdefault(trace_id, TraceTimeline(trace_id=trace_id))
            if cwe_id and cwe_id != "UNKNOWN":
                tl.cwe_id = cwe_id
            current = getattr(tl, stage)
            if current is None or ts < current:
                setattr(tl, stage, ts)
    return timelines


# ── Aggregation + reporting ───────────────────────────────────────────────

def aggregate(timelines: Iterable[TraceTimeline]) -> dict[str, CWEStats]:
    stats: dict[str, CWEStats] = {}
    for cwe_id, (name, target, note) in CWE_BASELINE.items():
        stats[cwe_id] = CWEStats(cwe_id=cwe_id, name=name,
                                 target_seconds=target, note=note)
    for tl in timelines:
        if not tl.complete():
            continue
        total = tl.total_seconds()
        if total is None or total < 0:
            continue
        bucket = stats.setdefault(
            tl.cwe_id,
            CWEStats(cwe_id=tl.cwe_id, name=tl.cwe_id, target_seconds=None),
        )
        bucket.samples.append(total)
    return stats


def render_markdown(stats: dict[str, CWEStats], source: str) -> str:
    rows = ["| CWE | Attack | Samples | Mean (s) | Median (s) | Target (s) | Δ vs target | Note |",
            "|---|---|---:|---:|---:|---:|---:|---|"]
    # Stable order: known CWEs first (by baseline order), then any unknowns.
    order = list(CWE_BASELINE.keys()) + [
        k for k in stats if k not in CWE_BASELINE
    ]
    for cwe_id in order:
        s = stats.get(cwe_id)
        if not s:
            continue
        mean = s.mean()
        median = s.median()
        target = s.target_seconds
        delta = (mean - target) if (mean is not None and target is not None) else None
        rows.append("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            s.cwe_id, s.name, len(s.samples),
            f"{mean:.2f}" if mean is not None else "—",
            f"{median:.2f}" if median is not None else "—",
            f"{target:.2f}" if target is not None else "—",
            f"{delta:+.2f}" if delta is not None else "—",
            s.note or "",
        ))
    return "\n".join([f"_Source: {source}_", ""] + rows)


def render_csv(stats: dict[str, CWEStats]) -> str:
    lines = ["cwe_id,name,samples,mean_s,median_s,stdev_s,target_s,delta_s,note"]
    for cwe_id, s in stats.items():
        mean = s.mean()
        median = s.median()
        stdev = s.stdev()
        target = s.target_seconds
        delta = (mean - target) if (mean is not None and target is not None) else None
        lines.append(
            f"{cwe_id},{s.name},{len(s.samples)},"
            f"{mean or ''},{median or ''},{stdev or ''},"
            f"{target or ''},{delta or ''},{s.note}"
        )
    return "\n".join(lines)


def render_json(stats: dict[str, CWEStats]) -> str:
    payload = {}
    for cwe_id, s in stats.items():
        payload[cwe_id] = {
            "name": s.name,
            "samples": len(s.samples),
            "mean_seconds":   s.mean(),
            "median_seconds": s.median(),
            "stdev_seconds":  s.stdev(),
            "target_seconds": s.target_seconds,
            "note": s.note,
        }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ── Entry point ───────────────────────────────────────────────────────────

def _now() -> float:
    # Wrapped for ease of monkeypatching in tests.
    import time
    return time.time()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loki-url",
                        default=os.environ.get("LOKI_URL", "http://localhost:3100"))
    parser.add_argument("--prometheus-url",
                        default=os.environ.get("PROMETHEUS_URL", "http://localhost:9090"))
    parser.add_argument("--source", choices=["auto", "loki", "prometheus"],
                        default="auto",
                        help="auto: try Loki, fall back to Prometheus")
    parser.add_argument("--window-seconds", type=int, default=3600,
                        help="Loki query window (default: 1h)")
    parser.add_argument("--format", choices=["md", "json", "csv"], default="md")
    parser.add_argument("--out", help="write to file instead of stdout")
    args = parser.parse_args()

    timelines: dict[str, TraceTimeline] = {}
    source_used = "none"
    if args.source in ("auto", "loki"):
        try:
            timelines = fetch_from_loki(args.loki_url, args.window_seconds)
            source_used = f"loki ({args.loki_url}, window={args.window_seconds}s)"
        except (urllib.error.URLError, urllib.error.HTTPError,
                json.JSONDecodeError) as exc:
            if args.source == "loki":
                print(f"Loki query failed: {exc}", file=sys.stderr)
                return 2
            print(f"[warn] Loki unreachable ({exc}); falling back to Prometheus",
                  file=sys.stderr)

    if not timelines and args.source in ("auto", "prometheus"):
        try:
            timelines = fetch_from_prometheus(args.prometheus_url)
            source_used = f"prometheus ({args.prometheus_url})"
        except (urllib.error.URLError, urllib.error.HTTPError,
                json.JSONDecodeError) as exc:
            print(f"Prometheus query failed: {exc}", file=sys.stderr)
            return 2

    stats = aggregate(timelines.values())

    if args.format == "md":
        out = render_markdown(stats, source_used)
    elif args.format == "csv":
        out = render_csv(stats)
    else:
        out = render_json(stats)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
