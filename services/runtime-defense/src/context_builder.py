"""Context package builder - assembles normalized event + CWE + source mapping
into the structured JSON context that Phase 2 consumes."""

from typing import Optional
from src.models import NormalizedEvent

PIPELINE_VERSION = "2.0.0"


def build_context(
    event: NormalizedEvent,
    cwe: dict,
    source_map: Optional[dict],
    defense_action: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> dict:
    return {
        "context_id": f"ctx-{event.event_id}",
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "attack_info": {
            "category": event.attack_category,
            "cwe_id": cwe["cwe_id"],
            "cwe_name": cwe["cwe_name"],
            "owasp_category": cwe.get("owasp", "UNKNOWN"),
            "payload_sample": event.payload_sample,
            "source_ip": event.source_ip,
            "blocked": event.blocked,
        },
        "target": {
            "endpoint": event.target_endpoint.model_dump(),
            "source_mapping": source_map,
        },
        "metadata": {
            "severity": event.severity,
            "pipeline_version": PIPELINE_VERSION,
            "detection_source": event.source,
            "defense_action_taken": defense_action,
            "requires_patch": cwe["cwe_id"] != "UNKNOWN",
            "trace_id": trace_id,
        },
    }
