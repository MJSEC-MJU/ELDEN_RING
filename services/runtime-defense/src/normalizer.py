"""Event normalizer - routes raw logs to the appropriate adapter."""

import logging
from src.adapters import ModSecurityAdapter, FalcoAdapter
from src.models import NormalizedEvent

logger = logging.getLogger(__name__)


class EventNormalizer:
    def __init__(self):
        self.adapters = [
            ModSecurityAdapter(),
            FalcoAdapter(),
        ]

    def normalize(self, raw_log: dict) -> NormalizedEvent:
        for adapter in self.adapters:
            if adapter.can_handle(raw_log):
                return adapter.parse(raw_log)
        raise ValueError(f"No adapter can handle this log: {list(raw_log.keys())}")
