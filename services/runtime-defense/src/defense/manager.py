"""Defense orchestration manager.

Tracks attack counts per IP and endpoint, escalates response levels:
  Lv.1: Rate Limit (all events)
  Lv.2: IP Block (>=3 attacks or HIGH+)
  Lv.3: Endpoint Disable (>=5 attacks or CRITICAL)
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone

from src.models import NormalizedEvent
from src.config import settings
from src.defense.rate_limiter import apply_rate_limit
from src.defense.ip_blocker import block_ip
from src.defense.endpoint_disabler import disable_endpoint

logger = logging.getLogger(__name__)


class DefenseManager:
    def __init__(self):
        self.ip_attack_count: dict[str, int] = defaultdict(int)
        self.endpoint_attack_count: dict[str, int] = defaultdict(int)
        self.action_history: list[dict] = []
        self._blocked_ips: set[str] = set()
        self._disabled_endpoints: set[str] = set()

    async def handle_defense(self, event: NormalizedEvent) -> str:
        """Execute defense actions based on event severity and repeat counts."""
        source_ip = event.source_ip
        endpoint_key = f"{event.target_endpoint.method} {event.target_endpoint.path}"

        if source_ip:
            self.ip_attack_count[source_ip] += 1
        self.endpoint_attack_count[endpoint_key] += 1

        actions_taken = []

        # Lv.1: Rate Limit (for all events with a source IP)
        if source_ip:
            await apply_rate_limit(source_ip, settings.RATE_LIMIT_RPM)
            actions_taken.append("rate_limit")
            self._record("rate_limit", source_ip, event.event_id)

        # Lv.2: IP Block
        if source_ip and source_ip not in self._blocked_ips and (
            self.ip_attack_count[source_ip] >= settings.IP_BLOCK_THRESHOLD
            or event.severity in ("HIGH", "CRITICAL")
        ):
            await block_ip(source_ip, settings.K8S_NAMESPACE)
            self._blocked_ips.add(source_ip)
            actions_taken.append("ip_blocked")
            self._record("ip_blocked", source_ip, event.event_id)

        # Lv.3: Endpoint Disable
        if endpoint_key not in self._disabled_endpoints and (
            self.endpoint_attack_count[endpoint_key] >= settings.ENDPOINT_DISABLE_THRESHOLD
            or event.severity == "CRITICAL"
        ):
            method, path = event.target_endpoint.method, event.target_endpoint.path
            await disable_endpoint(method, path, settings.K8S_NAMESPACE)
            self._disabled_endpoints.add(endpoint_key)
            actions_taken.append("endpoint_disabled")
            self._record("endpoint_disabled", endpoint_key, event.event_id)

        result = "+".join(actions_taken) if actions_taken else "none"
        logger.info(f"Defense actions for {event.event_id}: {result}")
        return result

    def _record(self, action: str, target: str, event_id: str):
        self.action_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": event_id,
            "action": action,
            "target": target,
        })

    def get_stats(self) -> dict:
        return {
            "ip_attack_counts": dict(self.ip_attack_count),
            "endpoint_attack_counts": dict(self.endpoint_attack_count),
            "blocked_ips": list(self._blocked_ips),
            "disabled_endpoints": list(self._disabled_endpoints),
        }
