"""Tier 1 검증: MAX_PATCH_RETRY 재시도 루프 + temperature 단계적 상승 + cache_control 적용."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from secure_coding_plane.config import PlaneSettings
from secure_coding_plane.llm_clients import (
    AnthropicSdkPatchClient,
    LlmPatchClientError,
    LlmStructuredResponse,
)
from secure_coding_plane.patching import SecureCodingPatchEngine
from secure_coding_plane.schemas import PatchStrategy


def _settings(tmp_path: Path, **overrides: Any) -> PlaneSettings:
    base = PlaneSettings(
        workspace_root=tmp_path / "ws",
        artifact_root=tmp_path / "art",
        db_path=tmp_path / "db.sqlite",
        redis_url=None,
        secure_coding_llm_provider="mock",
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _engine(settings: PlaneSettings) -> SecureCodingPatchEngine:
    engine = SecureCodingPatchEngine.__new__(SecureCodingPatchEngine)
    engine.settings = settings
    engine.store = MagicMock()
    engine.artifact_root = settings.artifact_root
    engine.patch_client = MagicMock()
    return engine


def _ok_response() -> LlmStructuredResponse:
    return LlmStructuredResponse(
        payload={"patched_snippet": "ok = True\n", "change_summary": {"security_fix": "fixed"}},
        raw_text="...",
        provider="test",
        model="test-model",
    )


def test_retry_loop_succeeds_on_first_attempt(tmp_path: Path) -> None:
    settings = _settings(tmp_path, secure_coding_max_patch_retry=3, secure_coding_llm_temperature=0.2)
    engine = _engine(settings)
    engine.patch_client.generate_patch_json.return_value = _ok_response()

    response, attempts, temp = engine._call_llm_with_retry("job-1", "prompt")

    assert attempts == 1
    assert temp == pytest.approx(0.2)
    assert response.payload["patched_snippet"] == "ok = True\n"
    engine.patch_client.generate_patch_json.assert_called_once()


def test_retry_loop_recovers_after_two_failures(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        secure_coding_max_patch_retry=3,
        secure_coding_llm_temperature=0.2,
        secure_coding_retry_temp_step=0.3,
    )
    engine = _engine(settings)
    engine.patch_client.generate_patch_json.side_effect = [
        LlmPatchClientError("bad1"),
        LlmPatchClientError("bad2"),
        _ok_response(),
    ]

    response, attempts, temp = engine._call_llm_with_retry("job-2", "prompt")

    assert attempts == 3
    assert temp == pytest.approx(0.8)  # 0.2 + 0.3 + 0.3
    assert response.provider == "test"
    assert engine.patch_client.generate_patch_json.call_count == 3
    # 각 호출의 temperature 가 단계적으로 상승했는지 확인
    temps = [call.kwargs["temperature"] for call in engine.patch_client.generate_patch_json.call_args_list]
    assert temps == pytest.approx([0.2, 0.5, 0.8])


def test_retry_caps_temperature(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        secure_coding_max_patch_retry=5,
        secure_coding_llm_temperature=0.5,
        secure_coding_retry_temp_step=0.4,
        secure_coding_retry_temp_cap=0.9,
    )
    engine = _engine(settings)
    engine.patch_client.generate_patch_json.side_effect = [
        LlmPatchClientError("e1"), LlmPatchClientError("e2"),
        LlmPatchClientError("e3"), _ok_response(),
    ]

    response, attempts, temp = engine._call_llm_with_retry("job-3", "prompt")

    assert attempts == 4
    temps = [call.kwargs["temperature"] for call in engine.patch_client.generate_patch_json.call_args_list]
    # 0.5, 0.9, 0.9 (capped), 0.9 (capped) — 0.5+0.4=0.9 OK, then +0.4 would be 1.3 -> capped
    assert temps[0] == pytest.approx(0.5)
    assert temps[1] == pytest.approx(0.9)
    assert temps[2] == pytest.approx(0.9)
    assert temps[3] == pytest.approx(0.9)
    assert temp == pytest.approx(0.9)


def test_retry_loop_raises_after_exhausting_retries(tmp_path: Path) -> None:
    settings = _settings(tmp_path, secure_coding_max_patch_retry=2)
    engine = _engine(settings)
    engine.patch_client.generate_patch_json.side_effect = LlmPatchClientError("nope")

    with pytest.raises(LlmPatchClientError) as exc_info:
        engine._call_llm_with_retry("job-4", "prompt")

    assert "after 2 attempts" in str(exc_info.value)
    assert engine.patch_client.generate_patch_json.call_count == 2


def test_retry_loop_treats_missing_snippet_as_failure(tmp_path: Path) -> None:
    settings = _settings(tmp_path, secure_coding_max_patch_retry=2)
    engine = _engine(settings)
    bad_response = LlmStructuredResponse(
        payload={"patched_snippet": "", "change_summary": {}},
        raw_text="bad",
        provider="test",
        model=None,
    )
    engine.patch_client.generate_patch_json.side_effect = [bad_response, _ok_response()]

    response, attempts, temp = engine._call_llm_with_retry("job-5", "prompt")

    assert attempts == 2
    assert response.payload["patched_snippet"] == "ok = True\n"


def test_anthropic_sdk_client_marks_system_blocks_with_cache_control_when_enabled(tmp_path: Path) -> None:
    """cache_control: ephemeral 가 prompt_cache_enabled=True 시 system block 에 부착되는지."""
    captured: dict[str, Any] = {}

    class FakeClient:
        class messages:  # noqa: N801 — mimic SDK API shape
            @staticmethod
            def create(**kwargs: Any) -> Any:
                captured.update(kwargs)
                class Resp:
                    content = [type("Block", (), {"type": "text",
                                                  "text": '{"patched_snippet":"x\\n","change_summary":{"security_fix":"y"}}'})()]
                    usage = type("U", (), {"input_tokens": 100, "output_tokens": 20,
                                           "cache_creation_input_tokens": 80, "cache_read_input_tokens": 0})()
                return Resp()

    client = AnthropicSdkPatchClient(
        api_key="sk-test",
        model="claude-sonnet-4-6",
        timeout_sec=10,
        max_tokens=2048,
        prompt_cache_enabled=True,
    )
    client._client = FakeClient()  # bypass lazy import

    resp = client.generate_patch_json(
        prompt="patch this",
        workdir=tmp_path,
        schema={"type": "object", "properties": {"patched_snippet": {"type": "string"}, "change_summary": {"type": "object"}}},
        temperature=0.4,
    )

    assert resp.payload["patched_snippet"] == "x\n"
    assert resp.usage == {"input_tokens": 100, "output_tokens": 20,
                         "cache_creation_input_tokens": 80, "cache_read_input_tokens": 0}
    # cache_control 가 system block 모두에 부착되었는가
    assert isinstance(captured["system"], list)
    for block in captured["system"]:
        assert block.get("cache_control") == {"type": "ephemeral"}, f"missing cache_control on {block}"
    # temperature 가 SDK 에 전달됐는가
    assert captured["temperature"] == pytest.approx(0.4)


def test_anthropic_sdk_client_omits_cache_control_when_disabled(tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                captured.update(kwargs)
                class Resp:
                    content = [type("B", (), {"type": "text",
                                              "text": '{"patched_snippet":"y\\n","change_summary":{}}'})()]
                    usage = None
                return Resp()

    client = AnthropicSdkPatchClient(
        api_key="sk-test",
        model="claude-sonnet-4-6",
        timeout_sec=10,
        max_tokens=2048,
        prompt_cache_enabled=False,
    )
    client._client = FakeClient()

    client.generate_patch_json(
        prompt="p",
        workdir=tmp_path,
        schema={"type": "object", "properties": {"patched_snippet": {"type": "string"}, "change_summary": {"type": "object"}}},
    )
    for block in captured["system"]:
        assert "cache_control" not in block
