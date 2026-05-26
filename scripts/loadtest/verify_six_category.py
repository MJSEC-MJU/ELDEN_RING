#!/usr/bin/env python3
"""Phase 1 Week 11 — 6-category × 5-mock-attack live verification.

Fires the **same 30 mock-attack payloads** used by the test suite
(``tests/test_six_category_detection.py``) against a running
runtime-defense controller, then asserts every one was processed and
mapped to the correct CWE.

Usage:
    python verify_six_category.py [--url URL] [--token BEARER] [--json]

Defaults to ``http://localhost:18080``. With ``--json`` the script
prints a machine-readable report instead of the human table; useful
for the demo-day evidence bundle.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

# Import the same corpus the unit tests use so they cannot drift.
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT / "services" / "runtime-defense"))

from tests.test_six_category_detection import (  # type: ignore  # noqa: E402
    DETECTION_CORPUS,
)


EXPECTED_TOTAL = 30


def _http_post(url: str, body: dict, token: str | None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode(errors="replace")}
    except urllib.error.URLError as e:
        return -1, {"error": str(e)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("PHASE1_URL", "http://localhost:18080"))
    parser.add_argument("--token", default=os.environ.get("WEBHOOK_AUTH_TOKEN", ""))
    parser.add_argument("--json", action="store_true", help="emit JSON report only")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    modsec_ep = f"{base}/api/v1/modsec-events"
    falco_ep = f"{base}/api/v1/falco-events"
    ctxs_ep = f"{base}/api/v1/contexts"

    results: list[dict] = []
    per_category_hits: dict[str, int] = defaultdict(int)
    per_category_total: dict[str, int] = defaultdict(int)

    for category, source, samples, expected_cwe in DETECTION_CORPUS:
        endpoint = modsec_ep if source == "modsecurity" else falco_ep
        for idx, sample in enumerate(samples, start=1):
            per_category_total[category] += 1
            status, body = _http_post(endpoint, sample, args.token)
            ctx_id = body.get("context_id")
            verdict = "unknown"
            actual_cwe = None

            if status == 200 and ctx_id:
                # Fetch the materialised context to read the resolved CWE
                fetch_headers = (
                    {"Authorization": f"Bearer {args.token}"} if args.token else {}
                )
                try:
                    req = urllib.request.Request(
                        f"{ctxs_ep}/{ctx_id}", headers=fetch_headers
                    )
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        ctx = json.loads(resp.read())
                        actual_cwe = ctx.get("attack_info", {}).get("cwe_id")
                except Exception as exc:  # noqa: BLE001 — purely diagnostic
                    actual_cwe = f"fetch-failed:{exc!r}"
                verdict = "detected" if actual_cwe == expected_cwe else "miscategorised"
                if verdict == "detected":
                    per_category_hits[category] += 1
            else:
                verdict = f"http_{status}"

            results.append({
                "category": category,
                "source": source,
                "sample_idx": idx,
                "expected_cwe": expected_cwe,
                "actual_cwe": actual_cwe,
                "context_id": ctx_id,
                "http_status": status,
                "verdict": verdict,
            })

    hits = sum(per_category_hits.values())
    report = {
        "controller_url": base,
        "expected_total": EXPECTED_TOTAL,
        "hits": hits,
        "miss_count": EXPECTED_TOTAL - hits,
        "per_category": {
            cat: {"hits": per_category_hits[cat], "total": per_category_total[cat]}
            for cat, _, _, _ in DETECTION_CORPUS
        },
        "results": results,
    }

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"\n=== Phase 1 6-category detection — {base} ===")
        print(f"{'Category':<32}{'CWE':<10}{'Hits':>8}")
        print("-" * 50)
        for cat, _, _, cwe in DETECTION_CORPUS:
            h = per_category_hits[cat]
            t = per_category_total[cat]
            mark = "OK" if h == t else "FAIL"
            print(f"{cat:<32}{cwe:<10}{f'{h}/{t}':>8}  [{mark}]")
        print("-" * 50)
        print(f"{'TOTAL':<32}{'':<10}{f'{hits}/{EXPECTED_TOTAL}':>8}")
        if hits != EXPECTED_TOTAL:
            print("\nMiscategorised / failed entries:")
            for r in results:
                if r["verdict"] != "detected":
                    print(f"  - {r['category']} #{r['sample_idx']}: {r['verdict']} "
                          f"(actual={r['actual_cwe']})")

    return 0 if hits == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
