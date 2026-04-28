"""Tests for the payload truncation helper used by all adapters."""

import pytest

from src.payload_utils import MAX_PAYLOAD_BYTES, TRUNCATION_MARKER, truncate_payload


class TestTruncatePayload:
    def test_short_string_passthrough(self):
        assert truncate_payload("hello") == "hello"

    def test_none_returns_empty(self):
        assert truncate_payload(None) == ""

    def test_bytes_decoded(self):
        assert truncate_payload(b"abc") == "abc"

    def test_invalid_bytes_replaced(self):
        # Lone continuation byte; must not raise.
        out = truncate_payload(b"good\x80bad")
        assert "good" in out

    def test_long_input_truncated(self):
        big = "A" * (MAX_PAYLOAD_BYTES * 2)
        out = truncate_payload(big)
        assert out.endswith(TRUNCATION_MARKER)
        # Body before the marker must not exceed the byte budget.
        body = out[: -len(TRUNCATION_MARKER)]
        assert len(body.encode("utf-8")) <= MAX_PAYLOAD_BYTES

    def test_custom_limit(self):
        out = truncate_payload("0123456789", max_bytes=4)
        assert out.startswith("0123")
        assert out.endswith(TRUNCATION_MARKER)

    def test_at_exact_boundary_not_truncated(self):
        s = "x" * MAX_PAYLOAD_BYTES
        assert truncate_payload(s) == s

    def test_multibyte_at_cut_point_dropped(self):
        # Each '한' = 3 bytes. 5 chars = 15 bytes. Cut at 10 bytes leaves
        # 3 complete chars (9 bytes) + truncation marker (the 10th byte
        # would split a char, errors='ignore' drops it).
        s = "한한한한한"
        out = truncate_payload(s, max_bytes=10)
        body = out[: -len(TRUNCATION_MARKER)]
        # Body must be valid UTF-8 (no replacement chars) and shorter than input.
        assert "�" not in body
        assert len(body) < len(s)
