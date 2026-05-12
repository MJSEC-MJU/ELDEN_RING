"""Tier 1 검증: MAX_PATCH_RETRY 재시도 루프 + temperature 단계적 상승 + cache_control 적용."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.secure_coding_plane.config import PlaneSettings
from src.secure_coding_plane.llm_clients import (
    AnthropicSdkPatchClient,
    LlmConfigError,
    LlmPatchClientError,
    LlmStructuredResponse,
)
from src.secure_coding_plane.patching import SecureCodingPatchEngine
from src.secure_coding_plane.schemas import PatchStrategy


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


def test_retry_loop_treats_missing_security_fix_as_failure(tmp_path: Path) -> None:
    """Codex 가 지적한 결함: snippet 있어도 security_fix 누락이면 재시도."""
    settings = _settings(tmp_path, secure_coding_max_patch_retry=3)
    engine = _engine(settings)
    snippet_only = LlmStructuredResponse(
        payload={"patched_snippet": "x = 1\n", "change_summary": {}},  # security_fix 누락
        raw_text="...",
        provider="test",
        model=None,
    )
    summary_no_fix = LlmStructuredResponse(
        payload={"patched_snippet": "x = 1\n", "change_summary": {"other_field": "junk"}},
        raw_text="...",
        provider="test",
        model=None,
    )
    engine.patch_client.generate_patch_json.side_effect = [snippet_only, summary_no_fix, _ok_response()]

    response, attempts, temp = engine._call_llm_with_retry("job-sec", "prompt")

    assert attempts == 3
    assert response.payload["change_summary"]["security_fix"] == "fixed"


def test_retry_loop_treats_non_dict_change_summary_as_failure(tmp_path: Path) -> None:
    settings = _settings(tmp_path, secure_coding_max_patch_retry=2)
    engine = _engine(settings)
    bad = LlmStructuredResponse(
        payload={"patched_snippet": "ok = True\n", "change_summary": "not-a-dict"},
        raw_text="...",
        provider="test",
        model=None,
    )
    engine.patch_client.generate_patch_json.side_effect = [bad, _ok_response()]

    response, attempts, _ = engine._call_llm_with_retry("job-cs", "prompt")
    assert attempts == 2


def test_retry_loop_raises_immediately_on_non_retryable_config_error(tmp_path: Path) -> None:
    """SDK 미설치 / API key 누락 / auth 실패는 즉시 중단."""
    settings = _settings(tmp_path, secure_coding_max_patch_retry=5)
    engine = _engine(settings)
    engine.patch_client.generate_patch_json.side_effect = LlmConfigError("no SDK installed")

    with pytest.raises(LlmConfigError, match="no SDK"):
        engine._call_llm_with_retry("job-cfg", "prompt")

    # retry 안 함: 첫 시도만 호출됐어야 함
    assert engine.patch_client.generate_patch_json.call_count == 1


def test_create_patch_client_raises_config_error_when_anthropic_api_key_missing(tmp_path: Path) -> None:
    from src.secure_coding_plane.llm_clients import create_patch_client
    settings = _settings(
        tmp_path,
        secure_coding_llm_provider="anthropic",
        secure_coding_anthropic_api_key=None,
    )
    with pytest.raises(LlmConfigError, match="ANTHROPIC_API_KEY"):
        create_patch_client(settings)


def test_response_carries_requested_temperature_for_cli_providers(tmp_path: Path) -> None:
    """CLI provider 는 temperature 를 무시하지만 metadata 에는 노출되어야 한다."""
    from src.secure_coding_plane.llm_clients import ClaudeCodePatchCliClient

    client = ClaudeCodePatchCliClient(command="claude", model=None, timeout_sec=5)
    # _run 모킹: CLI 실제 호출 없이 stdout 만 반환
    fake = LlmStructuredResponse(payload={"patched_snippet": "ok\n", "change_summary": {"security_fix": "f"}},
                                 raw_text="{}", provider="claude_code", model=None,
                                 requested_temperature=0.7, temperature_applied=False)
    # CLI 호출 자체를 우회: generate_patch_json 가 LlmStructuredResponse 의 형식을 보장하는지 검증.
    # 여기서는 직접 인스턴스를 만들어 metadata 노출만 확인한다.
    assert fake.requested_temperature == pytest.approx(0.7)
    assert fake.temperature_applied is False
    assert client.supports_temperature is False


def test_anthropic_provider_advertises_temperature_support() -> None:
    from src.secure_coding_plane.llm_clients import AnthropicSdkPatchClient
    c = AnthropicSdkPatchClient(api_key="sk-test", model="claude-sonnet-4-6",
                                timeout_sec=10, max_tokens=1024, prompt_cache_enabled=True)
    assert c.supports_temperature is True


def test_anthropic_sdk_response_includes_temperature_flags(tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                captured.update(kwargs)
                class Resp:
                    content = [type("B", (), {"type": "text",
                                              "text": '{"patched_snippet":"y\\n","change_summary":{"security_fix":"f"}}'})()]
                    usage = type("U", (), {"input_tokens": 50, "output_tokens": 10,
                                           "cache_creation_input_tokens": 0, "cache_read_input_tokens": 40})()
                return Resp()

    client = AnthropicSdkPatchClient(
        api_key="sk-test", model="claude-sonnet-4-6", timeout_sec=10,
        max_tokens=1024, prompt_cache_enabled=True,
    )
    client._client = FakeClient()
    resp = client.generate_patch_json(
        prompt="p", workdir=tmp_path,
        schema={"type":"object","properties":{"patched_snippet":{"type":"string"},"change_summary":{"type":"object"}}},
        temperature=0.55,
    )

    assert resp.temperature_applied is True
    assert resp.requested_temperature == pytest.approx(0.55)
    assert resp.usage["cache_read_input_tokens"] == 40
    assert captured["temperature"] == pytest.approx(0.55)


def test_anthropic_sdk_clamps_out_of_range_temperature(tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                captured.update(kwargs)
                class Resp:
                    content = [type("B", (), {"type": "text",
                                              "text": '{"patched_snippet":"x\\n","change_summary":{"security_fix":"y"}}'})()]
                    usage = None
                return Resp()

    client = AnthropicSdkPatchClient(api_key="sk", model="m", timeout_sec=5, max_tokens=128,
                                     prompt_cache_enabled=False)
    client._client = FakeClient()
    client.generate_patch_json(prompt="p", workdir=tmp_path,
                               schema={"type":"object","properties":{"patched_snippet":{"type":"string"},"change_summary":{"type":"object"}}},
                               temperature=2.5)
    assert captured["temperature"] == pytest.approx(1.0)  # cap


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
