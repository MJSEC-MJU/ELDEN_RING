"""Payload size enforcement for adapter outputs.

Caps every ``payload_sample`` at a fixed byte budget so large request
bodies (file uploads, base64 blobs) cannot blow up Redis/Phase 2.
The default (~1 KiB via settings.MAX_PAYLOAD_BYTES) is enough for the
patterns Phase 2 reasons about (SQLi/XSS/path traversal payloads are
typically tens of bytes).
"""

from src.config import settings

MAX_PAYLOAD_BYTES = settings.MAX_PAYLOAD_BYTES
TRUNCATION_MARKER = "...[truncated]"


def truncate_payload(value: object, max_bytes: int = MAX_PAYLOAD_BYTES) -> str:
    """Coerce *value* to text and clip to *max_bytes* UTF-8 bytes.

    Always returns a string. Bytes input is decoded with ``errors='replace'``
    so binary noise becomes printable. Multi-byte characters split by the
    cut point are dropped via ``errors='ignore'`` on the post-cut decode.
    """
    if value is None:
        return ""

    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)

    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text

    return encoded[:max_bytes].decode("utf-8", errors="ignore") + TRUNCATION_MARKER
