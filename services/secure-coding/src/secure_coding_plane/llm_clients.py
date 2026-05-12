from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PlaneSettings


class LlmPatchClientError(RuntimeError):
    """Retryable LLM error — 네트워크/일시적 응답 오류 등.
    patching.py retry 루프가 다음 시도를 진행한다."""
    pass


class LlmConfigError(LlmPatchClientError):
    """Non-retryable 환경/인증 오류 — SDK 미설치, API key 누락, auth 실패, CLI not found.
    재시도해도 동일 결과이므로 retry 루프가 즉시 중단해야 한다."""
    pass


@dataclass(slots=True)
class LlmStructuredResponse:
    payload: dict[str, Any]
    raw_text: str
    provider: str
    model: str | None
    usage: dict[str, int] | None = None              # input/output tokens, cache hits
    requested_temperature: float | None = None       # CLI provider 는 무시했더라도 기록
    temperature_applied: bool = False                # SDK 호출에 실제 적용됐는지


def create_patch_client(settings: PlaneSettings) -> "BasePatchCliClient":
    provider = settings.secure_coding_llm_provider.lower()
    if provider == "codex":
        return CodexPatchCliClient(
            command=settings.secure_coding_codex_command,
            model=settings.secure_coding_codex_model,
            timeout_sec=settings.secure_coding_llm_timeout_sec,
        )
    if provider in {"claude", "claude_code", "claude-code"}:
        return ClaudeCodePatchCliClient(
            command=settings.secure_coding_claude_command,
            model=settings.secure_coding_claude_model,
            timeout_sec=settings.secure_coding_llm_timeout_sec,
        )
    if provider in {"anthropic", "anthropic_sdk"}:
        if not settings.secure_coding_anthropic_api_key:
            raise LlmConfigError(
                "anthropic provider requires SECURE_CODING_ANTHROPIC_API_KEY (or ANTHROPIC_API_KEY)"
            )
        return AnthropicSdkPatchClient(
            api_key=settings.secure_coding_anthropic_api_key,
            model=settings.secure_coding_anthropic_model,
            timeout_sec=settings.secure_coding_llm_timeout_sec,
            max_tokens=settings.secure_coding_llm_max_tokens,
            prompt_cache_enabled=settings.secure_coding_prompt_cache_enabled,
        )
    raise LlmConfigError(f"Unsupported LLM provider: {settings.secure_coding_llm_provider}")


class BasePatchCliClient:
    provider_name: str
    supports_temperature: bool = False  # CLI wrappers default: 무시

    def __init__(self, *, command: str, model: str | None, timeout_sec: int) -> None:
        self.command = command
        self.model = model
        self.timeout_sec = timeout_sec
        self._auth_checked = False

    def generate_patch_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
        temperature: float | None = None,
    ) -> LlmStructuredResponse:
        raise NotImplementedError

    def _check_command_exists(self) -> None:
        if Path(self.command).exists():
            return
        if shutil.which(self.command):
            return
        raise LlmConfigError(f"{self.provider_name} CLI not found: {self.command}")

    def _check_authentication(self) -> None:
        raise NotImplementedError

    def _ensure_ready(self) -> None:
        self._check_command_exists()
        if not self._auth_checked:
            self._check_authentication()
            self._auth_checked = True

    def _run(self, args: list[str], *, cwd: Path, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            args,
            cwd=cwd,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=self.timeout_sec,
            check=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            stdout = completed.stdout.strip()
            detail = stderr or stdout or f"exit code {completed.returncode}"
            raise LlmPatchClientError(f"{self.provider_name} CLI call failed: {detail}")
        return completed

    def _parse_json_payload(self, raw_text: str) -> dict[str, Any]:
        text = raw_text.strip()
        if not text:
            raise LlmPatchClientError(f"{self.provider_name} returned empty output")
        candidates = [text]
        if "```" in text:
            parts = text.split("```")
            for idx in range(1, len(parts), 2):
                chunk = parts[idx]
                if "\n" in chunk:
                    chunk = chunk.split("\n", 1)[1]
                candidates.append(chunk.strip())
        decoder = json.JSONDecoder()
        for candidate in candidates:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass
            for start in range(len(candidate)):
                if candidate[start] not in "{[":
                    continue
                try:
                    payload, end = decoder.raw_decode(candidate[start:])
                except json.JSONDecodeError:
                    continue
                if candidate[start + end :].strip():
                    continue
                return payload
        raise LlmPatchClientError(f"{self.provider_name} output was not valid JSON")


class CodexPatchCliClient(BasePatchCliClient):
    provider_name = "codex"
    supports_temperature = False  # codex CLI 는 temperature 플래그를 노출하지 않음

    def _check_authentication(self) -> None:
        completed = self._run([self.command, "login", "status"], cwd=Path.cwd())
        login_status = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        if "Logged in" not in login_status:
            detail = login_status or "Codex login status unavailable"
            raise LlmConfigError(f"Codex OAuth session not ready: {detail}")

    def generate_patch_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
        temperature: float | None = None,
    ) -> LlmStructuredResponse:
        self._ensure_ready()
        with tempfile.TemporaryDirectory(prefix="codex-patch-") as tmp_dir:
            tmp_root = Path(tmp_dir)
            schema_path = tmp_root / "schema.json"
            output_path = tmp_root / "output.json"
            schema_path.write_text(json.dumps(schema, ensure_ascii=False), encoding="utf-8")
            args = [
                self.command,
                "exec",
                "--skip-git-repo-check",
                "-C",
                str(workdir),
                "--sandbox",
                "read-only",
                "--output-schema",
                str(schema_path),
                "-o",
                str(output_path),
            ]
            if self.model:
                args.extend(["-m", self.model])
            args.append("-")
            completed = self._run(args, cwd=workdir, input_text=prompt)
            raw_text = output_path.read_text(encoding="utf-8") if output_path.exists() else completed.stdout
            return LlmStructuredResponse(
                payload=self._parse_json_payload(raw_text),
                raw_text=raw_text,
                provider=self.provider_name,
                model=self.model,
                requested_temperature=temperature,
                temperature_applied=False,
            )


class ClaudeCodePatchCliClient(BasePatchCliClient):
    provider_name = "claude_code"
    supports_temperature = False  # claude CLI 는 temperature 플래그를 노출하지 않음

    def _check_authentication(self) -> None:
        completed = self._run([self.command, "auth", "status"], cwd=Path.cwd())
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise LlmConfigError("Claude auth status output was not valid JSON") from exc
        if not payload.get("loggedIn"):
            raise LlmConfigError("Claude Code OAuth session not ready. Run `claude auth login` first.")

    def generate_patch_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
        temperature: float | None = None,
    ) -> LlmStructuredResponse:
        self._ensure_ready()
        args = [
            self.command,
            "-p",
            "--permission-mode", "dontAsk",
            "--tools", "",
            "--output-format", "json",
            "--json-schema", json.dumps(schema),
        ]
        if self.model:
            args.extend(["--model", self.model])
        completed = self._run(args, cwd=workdir, input_text=prompt)
        raw_text = completed.stdout
        return LlmStructuredResponse(
            payload=self._extract_structured_output(raw_text),
            raw_text=raw_text,
            provider=self.provider_name,
            model=self.model,
            requested_temperature=temperature,
            temperature_applied=False,
        )

    def _extract_structured_output(self, raw_text: str) -> dict[str, Any]:
        try:
            wrapper = json.loads(raw_text)
        except json.JSONDecodeError:
            return self._parse_json_payload(raw_text)
        if isinstance(wrapper, dict):
            structured = wrapper.get("structured_output")
            if isinstance(structured, dict):
                return structured
            result = wrapper.get("result")
            if isinstance(result, dict):
                return result
            if isinstance(result, str) and result.strip():
                return self._parse_json_payload(result)
        return self._parse_json_payload(raw_text)


class AnthropicSdkPatchClient(BasePatchCliClient):
    """Direct Anthropic SDK 호출. temperature + prompt cache_control 가 실제 작동.

    CLI 래퍼 두 개(codex, claude_code) 와 달리 SDK 가 노출하는 모든 파라미터를 직접 제어한다.
    """

    provider_name = "anthropic"
    supports_temperature = True

    def __init__(self, *, api_key: str, model: str, timeout_sec: int, max_tokens: int, prompt_cache_enabled: bool) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout_sec = timeout_sec
        self.max_tokens = max_tokens
        self.prompt_cache_enabled = prompt_cache_enabled
        self._client = None

    def _client_lazy(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as e:
                raise LlmConfigError(
                    "anthropic Python SDK 미설치. requirements.txt 의 anthropic>=0.40 확인."
                ) from e
            self._client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout_sec)
        return self._client

    def _ensure_ready(self) -> None:
        if not self.api_key:
            raise LlmConfigError("anthropic API key not set")

    def generate_patch_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
        temperature: float | None = None,
    ) -> LlmStructuredResponse:
        self._ensure_ready()
        client = self._client_lazy()

        system_blocks = [
            {
                "type": "text",
                "text": (
                    "You are a secure code patch generator. You MUST output strict JSON matching "
                    "the provided schema with no markdown fences and no explanatory prose. "
                    "The 'patched_snippet' field must be a complete drop-in replacement for the "
                    "vulnerable code region; the 'change_summary' field must explain the security fix "
                    "in one sentence. Keep changes minimal and never add third-party dependencies."
                ),
            },
            {
                "type": "text",
                "text": "Response schema (must validate):\n" + json.dumps(schema, ensure_ascii=False),
            },
        ]
        if self.prompt_cache_enabled:
            for block in system_blocks:
                block["cache_control"] = {"type": "ephemeral"}

        user_messages = [
            {"role": "user", "content": prompt},
        ]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_blocks,
            "messages": user_messages,
        }
        applied_temp: float | None = None
        if temperature is not None:
            applied_temp = max(0.0, min(temperature, 1.0))
            kwargs["temperature"] = applied_temp

        try:
            response = client.messages.create(**kwargs)
        except Exception as e:
            etype = type(e).__name__
            # SDK 의 명확한 non-retryable 클래스들: 재시도해도 동일 결과
            if etype in {
                "AuthenticationError",
                "PermissionDeniedError",
                "BadRequestError",
                "NotFoundError",
                "UnprocessableEntityError",
            }:
                raise LlmConfigError(f"anthropic non-retryable {etype}: {e}") from e
            raise LlmPatchClientError(f"anthropic.messages.create failed ({etype}): {e}") from e

        text_chunks = []
        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_chunks.append(getattr(block, "text", ""))
        raw_text = "".join(text_chunks).strip()

        usage_obj = getattr(response, "usage", None)
        usage: dict[str, int] = {}
        if usage_obj is not None:
            for key in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
                val = getattr(usage_obj, key, None)
                if val is not None:
                    usage[key] = int(val)

        payload = self._parse_json_payload(raw_text)
        return LlmStructuredResponse(
            payload=payload,
            raw_text=raw_text,
            provider=self.provider_name,
            model=self.model,
            usage=usage or None,
            requested_temperature=temperature,
            temperature_applied=applied_temp is not None,
        )
