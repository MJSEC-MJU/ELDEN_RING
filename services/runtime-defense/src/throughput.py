"""1-minute sliding-window throughput counter for /diagnostics.

Prometheus already exposes a per-source ``runtime_defense_events_total``
counter, but ``/diagnostics`` needs a single scalar (events/sec averaged
over the last minute) without going through PromQL. This module keeps a
bounded deque of recent event timestamps and computes the rate on read.
"""

import collections
import threading
import time

_WINDOW_SECONDS = 60


class ThroughputTracker:
    def __init__(self, window_seconds: int = _WINDOW_SECONDS):
        self._window = window_seconds
        self._timestamps: collections.deque[float] = collections.deque()
        self._total = 0
        self._lock = threading.Lock()

    def record(self) -> None:
        now = time.monotonic()
        with self._lock:
            self._timestamps.append(now)
            self._total += 1
            self._trim(now)

    def events_per_sec(self) -> float:
        now = time.monotonic()
        with self._lock:
            self._trim(now)
            return len(self._timestamps) / self._window

    @property
    def total(self) -> int:
        return self._total

    def _trim(self, now: float) -> None:
        cutoff = now - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
