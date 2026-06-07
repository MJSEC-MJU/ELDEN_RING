"""Structured JSON logging with trace_id propagation.

Sets up the root logger to emit one JSON object per record with a
small set of standard fields (timestamp, level, logger, message,
trace_id). Trace IDs are stored in a ``ContextVar`` so coroutines
spawned from a request inherit the active value.

Phase 2/3/4 do not yet read ``trace_id``; that is captured as
cross-team handoff H-002. Generating it on the Phase 1 side is a
no-op for downstream consumers.
"""

import logging
import contextvars
import sys

try:
    # python-json-logger >= 3.x
    from pythonjsonlogger.json import JsonFormatter
except ImportError:  # pragma: no cover
    # python-json-logger 2.x
    from pythonjsonlogger.jsonlogger import JsonFormatter

from src.config import settings


trace_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "trace_id", default=""
)


class _TraceIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        record.trace_id = trace_id_var.get()
        return True


_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s %(trace_id)s"


def configure_logging() -> None:
    """Idempotently install JSON handler + trace filter on the root logger."""
    root = logging.getLogger()

    # Remove handlers from any prior basicConfig / reload to avoid duplicates.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter(_FORMAT, rename_fields={"asctime": "timestamp"})
    )
    handler.addFilter(_TraceIdFilter())

    root.addHandler(handler)
    root.setLevel(getattr(logging, settings.LOG_LEVEL, logging.INFO))


def set_trace_id(trace_id: str) -> contextvars.Token:
    return trace_id_var.set(trace_id)


def reset_trace_id(token: contextvars.Token) -> None:
    trace_id_var.reset(token)


def get_trace_id() -> str:
    return trace_id_var.get()
