"""Base adapter interface for security event sources."""

from abc import ABC, abstractmethod
from src.models import NormalizedEvent


class SecurityEventAdapter(ABC):
    @abstractmethod
    def can_handle(self, raw_log: dict) -> bool:
        """Return True if this adapter can parse the given raw log."""
        pass

    @abstractmethod
    def parse(self, raw_log: dict) -> NormalizedEvent:
        """Convert a raw log into a NormalizedEvent."""
        pass
