"""Base adapter interface for security event sources."""

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from src.models import NormalizedEvent


def generate_event_id() -> str:
    """Timestamped unique event id shared by all adapters."""
    return f"evt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


class SecurityEventAdapter(ABC):
    @abstractmethod
    def can_handle(self, raw_log: dict) -> bool:
        """Return True if this adapter can parse the given raw log."""
        pass

    @abstractmethod
    def parse(self, raw_log: dict) -> NormalizedEvent:
        """Convert a raw log into a NormalizedEvent."""
        pass
