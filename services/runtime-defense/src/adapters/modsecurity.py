"""ModSecurity audit log adapter.

Parses JSON audit logs from ModSecurity + OWASP CRS and converts them
into NormalizedEvent objects. Maps CRS Rule ID ranges to attack categories.
"""

from datetime import datetime, timezone

from src.adapters.base import SecurityEventAdapter, generate_event_id
from src.models import NormalizedEvent, TargetEndpoint
from src.payload_utils import truncate_payload

# CRS Rule ID range -> attack category
#
# Phase 1 Week 11 — detection scope expanded from 3 → 6 categories.
# We do NOT author new rules; we re-classify CRS hits into the CWE the
# Phase 2 patch worker keys off. Ranges are exclusive-upper (Python range).
#
# CRS reference (v3.3):
#   930xxx  LFI / Path Traversal             → CWE-22
#   932xxx  RCE / OS Command Injection        → CWE-78
#   934100-934129  Node.js Injection + SSRF   → CWE-918
#   934130-934999  PHP/Java Deserialization   → CWE-502
#   941xxx  XSS                               → CWE-79
#   942xxx  SQL Injection                     → CWE-89
MODSEC_RULE_CATEGORY_MAP = {
    range(942100, 943000): "SQL Injection",
    range(941100, 942000): "Cross-Site Scripting",
    range(930100, 931000): "Path Traversal",
    range(932100, 933000): "Command Injection",
    range(934100, 934130): "Server-Side Request Forgery",
    range(934130, 935000): "Insecure Deserialization",
}


class ModSecurityAdapter(SecurityEventAdapter):
    def can_handle(self, raw_log: dict) -> bool:
        return "transaction" in raw_log and "messages" in raw_log.get("audit_data", {})

    def parse(self, raw_log: dict) -> NormalizedEvent:
        transaction = raw_log.get("transaction", {})
        audit_data = raw_log.get("audit_data", {})
        messages = audit_data.get("messages", [])

        request_info = transaction.get("request", {})
        method = request_info.get("method", "UNKNOWN")
        uri = request_info.get("uri", "UNKNOWN")

        return NormalizedEvent(
            event_id=generate_event_id(),
            timestamp=transaction.get("time", datetime.now(timezone.utc).isoformat()),
            source="modsecurity",
            attack_category=self._extract_category(messages),
            target_endpoint=TargetEndpoint(method=method, path=uri),
            payload_sample=self._extract_payload(request_info),
            source_ip=transaction.get("remote_address"),
            blocked=True,  # ModSecurity On mode always blocks
            severity=self._assess_severity(messages),
            raw_rule_id=self._extract_rule_ids(messages),
        )

    def _extract_category(self, messages: list) -> str:
        for msg in messages:
            rule_id = msg.get("details", {}).get("ruleId", 0)
            if isinstance(rule_id, str):
                rule_id = int(rule_id)
            for id_range, category in MODSEC_RULE_CATEGORY_MAP.items():
                if rule_id in id_range:
                    return category
        return "Unknown Web Attack"

    def _assess_severity(self, messages: list) -> str:
        severities = [
            msg.get("details", {}).get("severity", "").upper() for msg in messages
        ]
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "WARNING" in severities or "ERROR" in severities:
            return "HIGH"
        return "MEDIUM"

    def _extract_payload(self, request_info: dict) -> str:
        body = request_info.get("body", "")
        if body:
            return truncate_payload(body)
        return truncate_payload(request_info.get("query_string", ""))

    def _extract_rule_ids(self, messages: list) -> str:
        rule_ids = [
            str(msg.get("details", {}).get("ruleId", "")) for msg in messages
        ]
        return ",".join(filter(None, rule_ids))
