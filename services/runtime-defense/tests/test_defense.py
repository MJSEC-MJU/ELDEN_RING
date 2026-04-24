"""Tests for defense manager logic."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from src.defense.manager import DefenseManager
from src.models import NormalizedEvent, TargetEndpoint


def _make_event(
    source_ip="192.168.1.100",
    severity="MEDIUM",
    method="POST",
    path="/api/login",
    event_id="evt-test",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source="modsecurity",
        attack_category="SQL Injection",
        target_endpoint=TargetEndpoint(method=method, path=path),
        payload_sample="test",
        source_ip=source_ip,
        blocked=True,
        severity=severity,
    )


@pytest.mark.asyncio
class TestDefenseManager:
    @patch("src.defense.manager.apply_rate_limit", new_callable=AsyncMock)
    @patch("src.defense.manager.block_ip", new_callable=AsyncMock)
    @patch("src.defense.manager.disable_endpoint", new_callable=AsyncMock)
    async def test_lv1_rate_limit_on_any_event(self, mock_disable, mock_block, mock_rate):
        mgr = DefenseManager()
        event = _make_event(severity="LOW")
        result = await mgr.handle_defense(event)
        assert "rate_limit" in result
        mock_rate.assert_called_once()

    @patch("src.defense.manager.apply_rate_limit", new_callable=AsyncMock)
    @patch("src.defense.manager.block_ip", new_callable=AsyncMock)
    @patch("src.defense.manager.disable_endpoint", new_callable=AsyncMock)
    async def test_lv2_ip_block_on_high_severity(self, mock_disable, mock_block, mock_rate):
        mgr = DefenseManager()
        event = _make_event(severity="HIGH")
        result = await mgr.handle_defense(event)
        assert "ip_blocked" in result
        mock_block.assert_called_once()

    @patch("src.defense.manager.apply_rate_limit", new_callable=AsyncMock)
    @patch("src.defense.manager.block_ip", new_callable=AsyncMock)
    @patch("src.defense.manager.disable_endpoint", new_callable=AsyncMock)
    async def test_lv3_endpoint_disable_on_critical(self, mock_disable, mock_block, mock_rate):
        mgr = DefenseManager()
        event = _make_event(severity="CRITICAL")
        result = await mgr.handle_defense(event)
        assert "endpoint_disabled" in result
        mock_disable.assert_called_once()

    @patch("src.defense.manager.apply_rate_limit", new_callable=AsyncMock)
    @patch("src.defense.manager.block_ip", new_callable=AsyncMock)
    @patch("src.defense.manager.disable_endpoint", new_callable=AsyncMock)
    async def test_lv2_on_repeat_attacks(self, mock_disable, mock_block, mock_rate):
        mgr = DefenseManager()
        for i in range(3):
            result = await mgr.handle_defense(
                _make_event(severity="MEDIUM", event_id=f"evt-{i}")
            )
        # 3rd attack should trigger IP block
        assert "ip_blocked" in result

    @patch("src.defense.manager.apply_rate_limit", new_callable=AsyncMock)
    @patch("src.defense.manager.block_ip", new_callable=AsyncMock)
    @patch("src.defense.manager.disable_endpoint", new_callable=AsyncMock)
    async def test_lv3_on_repeat_endpoint_attacks(self, mock_disable, mock_block, mock_rate):
        mgr = DefenseManager()
        for i in range(5):
            result = await mgr.handle_defense(
                _make_event(severity="LOW", event_id=f"evt-{i}", source_ip=f"10.0.0.{i}")
            )
        # 5th attack on same endpoint should trigger disable
        assert "endpoint_disabled" in result

    @patch("src.defense.manager.apply_rate_limit", new_callable=AsyncMock)
    @patch("src.defense.manager.block_ip", new_callable=AsyncMock)
    @patch("src.defense.manager.disable_endpoint", new_callable=AsyncMock)
    async def test_stats_tracking(self, mock_disable, mock_block, mock_rate):
        mgr = DefenseManager()
        await mgr.handle_defense(_make_event())
        stats = mgr.get_stats()
        assert "192.168.1.100" in stats["ip_attack_counts"]
        assert stats["ip_attack_counts"]["192.168.1.100"] == 1
