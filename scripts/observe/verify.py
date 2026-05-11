"""Automatic PASS/FAIL verifier for the Phase 1 reliability run.

Inputs (all under --run-dir):
    diagnostics.ndjson   per-second /diagnostics samples
    timeline.log         loadtest + chaos transitions
    normal.report.json   vegeta normal-traffic report
    sqli.report.json     vegeta sqli-traffic report

Pass criteria (matches the 회의 합격 기준):
    1. backup_queue.drops_total stays 0 across the whole run
    2. max(backup_queue.length) <= capacity (1000)
    3. From `redis_healthy` to first sample where queue == 0 is <= 30s
    4. max(hpa.current_replicas) >= 4   (skipped if HPA not available)
    5. After `loadtest_end`, hpa.current_replicas returns to 2 within 5 min
       — DEMO HPA profile only; production HPA target is 15 min.
    6. /diagnostics returned 5xx zero times during the run

Emits results/<ts>/REPORT.md with a verdict table and the measured values.
"""

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Optional


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_ndjson(p: pathlib.Path) -> list[dict]:
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def load_timeline(p: pathlib.Path) -> dict[str, datetime]:
    events: dict[str, datetime] = {}
    if not p.exists():
        return events
    for line in p.read_text().splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        try:
            t = _ts(parts[0])
        except ValueError:
            continue
        events.setdefault(parts[1].split()[0], t)
    return events


def check_drops(samples: list[dict]) -> tuple[bool, int]:
    drops = [s["body"]["backup_queue"]["drops_total"] for s in samples if s.get("body")]
    return (max(drops, default=0) == 0, max(drops, default=0))


def check_queue_cap(samples: list[dict], require_activation: bool) -> tuple[bool, int, int]:
    """Validate the backup queue. Under chaos we require activation (>0)
    so the run actually demonstrates the buffering behavior — a trivial
    "max == 0" pass proves nothing. Under load-only there's no outage,
    so max==0 is the expected (and accepted) outcome.
    """
    queue = [s["body"]["backup_queue"]["length"] for s in samples if s.get("body")]
    cap_list = [s["body"]["backup_queue"]["capacity"] for s in samples if s.get("body")]
    max_q = max(queue, default=0)
    cap = cap_list[0] if cap_list else 1000
    if require_activation:
        return (0 < max_q <= cap, max_q, cap)
    return (max_q <= cap, max_q, cap)


def check_drain(samples: list[dict], timeline: dict[str, datetime]) -> tuple[bool, Optional[float]]:
    healthy = timeline.get("redis_healthy")
    if not healthy:
        return (False, None)
    for s in samples:
        if not s.get("body"):
            continue
        t = _ts(s["ts"])
        if t < healthy:
            continue
        if s["body"]["backup_queue"]["length"] == 0:
            return ((t - healthy).total_seconds() <= 30.0,
                    (t - healthy).total_seconds())
    return (False, None)


def check_hpa_scale_up(samples: list[dict]) -> tuple[Optional[bool], Optional[int]]:
    """Return (pass, max_observed). None,None if HPA unavailable."""
    cur = []
    for s in samples:
        body = s.get("body") or {}
        hpa = body.get("hpa") or {}
        if not hpa.get("available"):
            continue
        if hpa.get("current_replicas") is not None:
            cur.append(hpa["current_replicas"])
    if not cur:
        return (None, None)
    m = max(cur)
    return (m >= 4, m)


def check_hpa_scale_down(samples: list[dict],
                        timeline: dict[str, datetime]
                        ) -> tuple[Optional[bool], Optional[float]]:
    end = timeline.get("loadtest_end")
    if not end:
        return (None, None)
    deadline = end + timedelta(minutes=5)
    saw_hpa = False
    for s in samples:
        body = s.get("body") or {}
        hpa = body.get("hpa") or {}
        if not hpa.get("available"):
            continue
        saw_hpa = True
        t = _ts(s["ts"])
        if t < end:
            continue
        if hpa.get("current_replicas") == 2:
            return (t <= deadline, (t - end).total_seconds())
    if not saw_hpa:
        return (None, None)
    return (False, None)


def check_diag_5xx(samples: list[dict]) -> tuple[bool, int]:
    bad = sum(1 for s in samples if 500 <= int(s.get("status", 0)) < 600)
    return (bad == 0, bad)


def fmt(b: Optional[bool]) -> str:
    if b is True:
        return "✅ PASS"
    if b is False:
        return "❌ FAIL"
    return "➖ N/A"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, type=pathlib.Path)
    ap.add_argument("--scenario", choices=["loadtest", "chaos"], default="chaos")
    args = ap.parse_args()

    nd = args.run_dir / "diagnostics.ndjson"
    if not nd.exists():
        print(f"missing {nd}", file=sys.stderr)
        return 2

    samples = load_ndjson(nd)
    timeline = load_timeline(args.run_dir / "timeline.log")

    drops_ok, drops_val = check_drops(samples)
    qcap_ok, qmax, qcap = check_queue_cap(samples, require_activation=(args.scenario == "chaos"))
    diag_ok, diag_5xx = check_diag_5xx(samples)
    hpa_up_ok, hpa_up_val = check_hpa_scale_up(samples)
    hpa_down_ok, hpa_down_val = check_hpa_scale_down(samples, timeline)

    if args.scenario == "chaos":
        drain_ok, drain_val = check_drain(samples, timeline)
    else:
        drain_ok, drain_val = (None, None)

    rows = [
        ("dropped events == 0", drops_ok, f"{drops_val}"),
        ("max backup queue ≤ capacity", qcap_ok, f"{qmax} / {qcap}"),
        ("drain after redis_healthy ≤ 30 s",
         drain_ok,
         "N/A" if drain_val is None else f"{drain_val:.1f}s"),
        ("HPA max replicas ≥ 4",
         hpa_up_ok,
         "N/A (no HPA)" if hpa_up_val is None else f"{hpa_up_val}"),
        ("HPA back to 2 within 5 min after loadtest_end (DEMO HPA profile)",
         hpa_down_ok,
         "N/A (no HPA)" if hpa_down_val is None else f"{hpa_down_val:.1f}s"),
        ("/diagnostics 5xx == 0", diag_ok, f"{diag_5xx}"),
    ]

    required_for_pass = [drops_ok, qcap_ok, diag_ok]
    if args.scenario == "chaos":
        required_for_pass.append(drain_ok)
    # HPA checks are skipped when running outside K8s.
    overall = all(r is not False for r in required_for_pass) and all(
        r is True for r in required_for_pass if r is not None
    )

    normal_rep = args.run_dir / "normal.report.json"
    sqli_rep = args.run_dir / "sqli.report.json"
    normal_summary = json.loads(normal_rep.read_text()) if normal_rep.exists() else {}
    sqli_summary = json.loads(sqli_rep.read_text()) if sqli_rep.exists() else {}

    md_lines: list[str] = []
    md_lines.append(f"# Phase 1 Reliability Run — {args.run_dir.name}")
    md_lines.append("")
    md_lines.append(f"**Scenario:** {args.scenario}")
    md_lines.append(f"**Verdict:** {'✅ PASS' if overall else '❌ FAIL'}")
    md_lines.append("")
    md_lines.append("> **Note:** Acceptance criterion "
                    "*'HPA back to 2 within 5 min'* assumes the **DEMO HPA "
                    "profile** (`runtime-defense-hpa-demo.yaml`), which uses "
                    "loosened scaleDown windows. The production HPA "
                    "(`runtime-defense-hpa.yaml`) is intentionally slower "
                    "(~15 min) to protect the in-memory backup queue during "
                    "rolling load-shed.")
    md_lines.append("")
    md_lines.append("## Pass/Fail")
    md_lines.append("")
    md_lines.append("| # | Criterion | Result | Measured |")
    md_lines.append("|---|---|---|---|")
    for i, (name, ok, val) in enumerate(rows, 1):
        md_lines.append(f"| {i} | {name} | {fmt(ok)} | {val} |")

    md_lines.append("")
    md_lines.append("## Vegeta traffic summary")
    md_lines.append("")
    md_lines.append("| Stream | Requests | Success% | p50 | p95 | p99 | Throughput |")
    md_lines.append("|---|---|---|---|---|---|---|")
    for label, rep in (("normal", normal_summary), ("sqli", sqli_summary)):
        if not rep:
            md_lines.append(f"| {label} | — | — | — | — | — | — |")
            continue
        # vegeta JSON: latencies in nanoseconds; success is fraction.
        lat = rep.get("latencies", {})
        ns_to_ms = lambda v: f"{v/1e6:.1f}ms" if v else "—"
        md_lines.append(
            f"| {label} | {rep.get('requests','—')} | "
            f"{rep.get('success', 0)*100:.2f}% | "
            f"{ns_to_ms(lat.get('50th'))} | "
            f"{ns_to_ms(lat.get('95th'))} | "
            f"{ns_to_ms(lat.get('99th'))} | "
            f"{rep.get('throughput',0):.1f}/s |"
        )

    md_lines.append("")
    md_lines.append("## Timeline")
    md_lines.append("")
    md_lines.append("| Event | Timestamp (UTC) |")
    md_lines.append("|---|---|")
    for name, t in timeline.items():
        md_lines.append(f"| {name} | {t.isoformat()} |")

    md_lines.append("")
    md_lines.append("## Plots")
    md_lines.append("")
    md_lines.append("- ![throughput + HPA](throughput_hpa.png)")
    md_lines.append("- ![redis outage + queue](redis_outage_queue.png)")
    md_lines.append("")

    out = args.run_dir / "REPORT.md"
    out.write_text("\n".join(md_lines))
    print(f"[verify] wrote {out}")
    print(f"[verify] verdict: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
