from __future__ import annotations

import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class IncidentRecord:
    incident_id: str
    started_at: float
    last_at: float
    phase1: dict[str, Any] | None = None
    phase2: dict[str, Any] | None = None
    phase3: dict[str, Any] | None = None
    phase4_stage: str = "pending"
    risk: str | None = None
    cwe_id: str | None = None
    severity: str | None = None
    candidate_image: str | None = None
    branch: str | None = None
    timeline: list[dict[str, Any]] = field(default_factory=list)


class PipelineState:
    MAX_EVENTS = 500
    MAX_INCIDENTS = 200

    def __init__(self) -> None:
        self.events: deque[dict[str, Any]] = deque(maxlen=self.MAX_EVENTS)
        self.incidents: dict[str, IncidentRecord] = {}
        self.totals_by_channel: Counter[str] = Counter()

    def push_event(self, channel: str, payload: dict[str, Any]) -> dict[str, Any]:
        ts = time.time()
        self.totals_by_channel[channel] += 1

        incident_id = self._extract_incident_id(channel, payload)
        event = {
            "ts": ts,
            "channel": channel,
            "incident_id": incident_id,
            "summary": self._summarize(channel, payload),
        }
        self.events.append(event)

        if incident_id:
            self._merge_into_incident(incident_id, channel, payload, ts)
        return event

    def _extract_incident_id(self, channel: str, payload: dict[str, Any]) -> str | None:
        if channel == "elden:phase2:context":
            return payload.get("event_id")
        if channel == "elden:phase3:validate":
            return payload.get("event_id")
        if channel == "elden:phase4:promote":
            p2 = payload.get("phase2") or {}
            return p2.get("event_id") or payload.get("incident_id")
        if channel == "elden:phase2:retry":
            return payload.get("incident_id") or payload.get("event_id")
        return None

    def _summarize(self, channel: str, payload: dict[str, Any]) -> str:
        if channel == "elden:phase2:context":
            ai = payload.get("attack_info") or {}
            return f"{ai.get('category','?')} {ai.get('cwe_id','')}"
        if channel == "elden:phase3:validate":
            return f"patch {payload.get('patch_id','?')} -> validate"
        if channel == "elden:phase4:promote":
            v = [payload.get(k, "?")[:1] for k in ("exploit", "regression", "slo")]
            return f"verdict E{v[0]}/R{v[1]}/S{v[2]}"
        if channel == "elden:phase2:retry":
            return f"retry: {payload.get('reason','?')}"
        return ""

    def _merge_into_incident(
        self, incident_id: str, channel: str, payload: dict[str, Any], ts: float
    ) -> None:
        rec = self.incidents.get(incident_id)
        if rec is None:
            if len(self.incidents) >= self.MAX_INCIDENTS:
                oldest = min(self.incidents.values(), key=lambda r: r.last_at)
                self.incidents.pop(oldest.incident_id, None)
            rec = IncidentRecord(incident_id=incident_id, started_at=ts, last_at=ts)
            self.incidents[incident_id] = rec
        rec.last_at = ts
        rec.timeline.append({"ts": ts, "channel": channel})

        if channel == "elden:phase2:context":
            rec.phase1 = payload
            rec.cwe_id = (payload.get("attack_info") or {}).get("cwe_id")
            rec.severity = (payload.get("metadata") or {}).get("severity")
            rec.phase4_stage = "phase1_done"
        elif channel == "elden:phase3:validate":
            rec.phase2 = payload
            rec.candidate_image = payload.get("candidate_image")
            rec.phase4_stage = "phase2_done"
        elif channel == "elden:phase4:promote":
            rec.phase3 = {
                "exploit": payload.get("exploit"),
                "regression": payload.get("regression"),
                "slo": payload.get("slo"),
                "llm": payload.get("phase3_llm"),
            }
            rec.risk = payload.get("risk") or rec.risk
            rec.branch = payload.get("branch") or rec.branch
            rec.phase4_stage = "phase3_done"
        elif channel == "elden:phase2:retry":
            rec.phase4_stage = "rejected"

    def update_phase4(self, governance_incidents: list[dict[str, Any]]) -> None:
        by_id = {gi.get("incident_id"): gi for gi in governance_incidents}
        for rid, rec in self.incidents.items():
            gi = by_id.get(rid)
            if not gi:
                continue
            risk = gi.get("risk")
            branch = gi.get("branch")
            stage = gi.get("stage", rec.phase4_stage)
            if risk != rec.risk or branch != rec.branch or stage != rec.phase4_stage:
                rec.last_at = time.time()
            rec.risk = risk
            rec.branch = branch
            rec.phase4_stage = stage

    def snapshot_incidents(self) -> list[dict[str, Any]]:
        out = []
        for rec in sorted(self.incidents.values(), key=lambda r: r.last_at, reverse=True):
            out.append({
                "incident_id": rec.incident_id,
                "started_at": rec.started_at,
                "last_at": rec.last_at,
                "duration_seconds": self._duration_seconds(rec),
                "stage": rec.phase4_stage,
                "risk": rec.risk,
                "cwe_id": rec.cwe_id,
                "severity": rec.severity,
                "candidate_image": rec.candidate_image,
                "branch": rec.branch,
                "phase1": rec.phase1,
                "phase2": rec.phase2,
                "phase3": rec.phase3,
                "timeline": rec.timeline,
            })
        return out

    def stats(self) -> dict[str, Any]:
        cwe_counter: Counter[str] = Counter()
        cwe_duration_totals: defaultdict[str, float] = defaultdict(float)
        cwe_recent: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        risk_counter: Counter[str] = Counter()
        stage_counter: Counter[str] = Counter()
        for r in self.incidents.values():
            duration = self._duration_seconds(r)
            if r.cwe_id:
                cwe_counter[r.cwe_id] += 1
                cwe_duration_totals[r.cwe_id] += duration
                cwe_recent[r.cwe_id].append(
                    {
                        "incident_id": r.incident_id,
                        "stage": r.phase4_stage,
                        "risk": r.risk,
                        "duration_seconds": duration,
                        "last_at": r.last_at,
                    }
                )
            if r.risk:
                risk_counter[r.risk] += 1
            stage_counter[r.phase4_stage] += 1
        cwe_breakdown = {
            cwe_id: {
                "count": count,
                "avg_duration_seconds": round(cwe_duration_totals[cwe_id] / count, 3),
                "recent_incidents": sorted(
                    cwe_recent[cwe_id],
                    key=lambda item: item["last_at"],
                    reverse=True,
                )[:5],
            }
            for cwe_id, count in cwe_counter.items()
        }
        return {
            "total_incidents": len(self.incidents),
            "total_events": sum(self.totals_by_channel.values()),
            "by_channel": dict(self.totals_by_channel),
            "by_cwe": dict(cwe_counter),
            "cwe_breakdown": cwe_breakdown,
            "by_risk": dict(risk_counter),
            "by_stage": dict(stage_counter),
        }

    @staticmethod
    def _duration_seconds(rec: IncidentRecord) -> float:
        return round(max(0.0, rec.last_at - rec.started_at), 3)
