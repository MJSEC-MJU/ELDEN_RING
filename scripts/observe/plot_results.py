"""Render Phase 1 reliability plots from a single run directory.

Reads ``diagnostics.ndjson`` (per-second samples of /diagnostics) and
``timeline.log`` (loadtest + chaos transitions) and produces two PNGs
that go straight onto the 11-주차 발표 슬라이드:

    throughput_hpa.png       — events/sec + HPA replicas over time
    redis_outage_queue.png   — redis_up + backup queue + drops, with
                                outage window shaded

Usage:
    python scripts/observe/plot_results.py \
        --run-dir scripts/loadtest/results/latest
"""

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt


def _parse_ts(s: str) -> datetime:
    # tolerate trailing 'Z'
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_ndjson(path: pathlib.Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def load_timeline(path: pathlib.Path) -> dict[str, datetime]:
    """Return the first timestamp for each named event."""
    events: dict[str, datetime] = {}
    if not path.exists():
        return events
    for line in path.read_text().splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        ts_raw, name = parts
        try:
            ts = _parse_ts(ts_raw)
        except ValueError:
            continue
        # take the FIRST occurrence so we measure from the earliest stamp
        events.setdefault(name.strip().split()[0], ts)
    return events


def extract_series(rows: list[dict]):
    ts, eps, replicas, queue, drops, redis_up = [], [], [], [], [], []
    for r in rows:
        body = r.get("body")
        if not body:
            continue
        try:
            t = _parse_ts(r["ts"])
        except (KeyError, ValueError):
            continue
        ts.append(t)
        eps.append(body.get("throughput", {}).get("events_per_sec_1m", 0.0))
        hpa = body.get("hpa", {}) or {}
        replicas.append(hpa.get("current_replicas") if hpa.get("available") else None)
        q = body.get("backup_queue", {})
        queue.append(q.get("length", 0))
        drops.append(q.get("drops_total", 0))
        redis_up.append(1 if body.get("redis", {}).get("up") else 0)
    return ts, eps, replicas, queue, drops, redis_up


def plot_throughput_hpa(out: pathlib.Path, ts, eps, replicas, timeline):
    fig, ax1 = plt.subplots(figsize=(10, 4.5))
    ax1.plot(ts, eps, color="#1f77b4", label="events/sec (1m sliding)")
    ax1.set_xlabel("time (UTC)")
    ax1.set_ylabel("events/sec", color="#1f77b4")
    ax1.tick_params(axis="y", labelcolor="#1f77b4")
    ax1.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))

    ax2 = ax1.twinx()
    if any(r is not None for r in replicas):
        ax2.step(ts, [r if r is not None else 0 for r in replicas],
                 color="#d62728", where="post", label="HPA current_replicas")
        ax2.set_ylabel("HPA replicas", color="#d62728")
        ax2.tick_params(axis="y", labelcolor="#d62728")
        ax2.set_ylim(0, 6)
    else:
        ax2.set_yticks([])
        ax2.text(0.99, 0.95, "HPA not available\n(non-cluster run)",
                 transform=ax2.transAxes, ha="right", va="top",
                 fontsize=8, color="#888")

    # Shade the Redis-outage window so plot A also shows when the queue
    # was active — this is the slide's key visual claim: throughput
    # holds at ~250 eps even while Redis is down.
    stop = timeline.get("redis_stopped")
    healthy = timeline.get("redis_healthy")
    if stop and healthy:
        ax1.axvspan(stop, healthy, color="red", alpha=0.10)
        ax1.text(stop, ax1.get_ylim()[1] * 0.95, "redis outage",
                 rotation=90, fontsize=7, color="red", va="top")

    for name, t in timeline.items():
        if name in ("loadtest_start", "loadtest_end"):
            ax1.axvline(t, color="#2ca02c", linestyle=":", alpha=0.5)
            ax1.text(t, ax1.get_ylim()[1] * 0.95, name, rotation=90,
                     fontsize=7, color="#2ca02c", va="top")

    plt.title("Scenario A: throughput + HPA replicas")
    fig.tight_layout()
    fig.savefig(out, dpi=140)
    plt.close(fig)


def plot_redis_outage(out: pathlib.Path, ts, queue, drops, redis_up, timeline):
    fig, ax1 = plt.subplots(figsize=(10, 4.5))
    ax1.plot(ts, queue, color="#ff7f0e", label="backup queue length")
    ax1.plot(ts, drops, color="#9467bd", label="drops (cumulative)")
    ax1.set_xlabel("time (UTC)")
    ax1.set_ylabel("count")
    ax1.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax1.legend(loc="upper left")

    ax2 = ax1.twinx()
    ax2.step(ts, redis_up, color="#17becf", where="post",
             label="redis_up (0/1)", alpha=0.6)
    ax2.set_ylabel("redis_up", color="#17becf")
    ax2.set_ylim(-0.1, 1.2)
    ax2.tick_params(axis="y", labelcolor="#17becf")

    stop = timeline.get("redis_stopped")
    healthy = timeline.get("redis_healthy")
    if stop and healthy:
        ax1.axvspan(stop, healthy, color="red", alpha=0.10, label="redis outage")
        ax1.text(stop, ax1.get_ylim()[1] * 0.95, "redis_stopped",
                 rotation=90, fontsize=7, color="red", va="top")
        ax1.text(healthy, ax1.get_ylim()[1] * 0.95, "redis_healthy",
                 rotation=90, fontsize=7, color="red", va="top")

    plt.title("Scenario B: Redis outage + backup queue drain")
    fig.tight_layout()
    fig.savefig(out, dpi=140)
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, type=pathlib.Path)
    args = ap.parse_args()

    nd = args.run_dir / "diagnostics.ndjson"
    if not nd.exists():
        print(f"[plot] missing {nd}", file=sys.stderr)
        return 1

    rows = load_ndjson(nd)
    timeline = load_timeline(args.run_dir / "timeline.log")
    ts, eps, replicas, queue, drops, redis_up = extract_series(rows)
    if not ts:
        print("[plot] no usable samples", file=sys.stderr)
        return 1

    plot_throughput_hpa(args.run_dir / "throughput_hpa.png",
                        ts, eps, replicas, timeline)
    plot_redis_outage(args.run_dir / "redis_outage_queue.png",
                      ts, queue, drops, redis_up, timeline)
    print(f"[plot] wrote {args.run_dir}/throughput_hpa.png")
    print(f"[plot] wrote {args.run_dir}/redis_outage_queue.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
