"""Falco event adapter.

Handles system-level events from Falco Sidekick webhooks:
shell execution, file tampering, privilege escalation, suspicious network.
"""

import uuid
from datetime import datetime, timezone

from src.adapters.base import SecurityEventAdapter
from src.models import NormalizedEvent, TargetEndpoint

FALCO_CATEGORY_MAP = {
    "shell": "Shell Execution",
    "network": "Suspicious Network",
    "filesystem": "File Tampering",
    "privilege-escalation": "Privilege Escalation",
}

FALCO_PRIORITY_MAP = {
    "Critical": "CRITICAL",
    "Error": "HIGH",
    "Warning": "MEDIUM",
    "Notice": "LOW",
    "Informational": "LOW",
    "Debug": "LOW",
}


def _generate_event_id() -> str:
    return f"evt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


class FalcoAdapter(SecurityEventAdapter):
    def can_handle(self, raw_log: dict) -> bool:
        return "rule" in raw_log and "output_fields" in raw_log

    def parse(self, raw_log: dict) -> NormalizedEvent:
        tags = raw_log.get("tags", [])
        category = "Unknown"
        for tag in tags:
            if tag in FALCO_CATEGORY_MAP:
                category = FALCO_CATEGORY_MAP[tag]
                break

        output_fields = raw_log.get("output_fields", {})

        return NormalizedEvent(
            event_id=_generate_event_id(),
            timestamp=raw_log.get("time", datetime.now(timezone.utc).isoformat()),
            source="falco",
            attack_category=category,
            target_endpoint=TargetEndpoint(
                method="SYSCALL",
                path=output_fields.get("k8s.pod.name", "UNKNOWN"),
            ),
            payload_sample=raw_log.get("output", ""),
            source_ip=output_fields.get("fd.sip"),
            blocked=False,
            severity=FALCO_PRIORITY_MAP.get(raw_log.get("priority", ""), "LOW"),
            raw_rule_id=raw_log.get("rule", ""),
        )
