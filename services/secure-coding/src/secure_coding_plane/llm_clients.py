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
    pass


@dataclass(slots=True)
class LlmStructuredResponse:
    payload: dict[str, Any]
    raw_text: str
    provider: str
    model: str | None


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
    raise LlmPatchClientError(f"Unsupported LLM provider: {settings.secure_coding_llm_provider}")


class BasePatchCliClient:
    provider_name: str

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
    ) -> LlmStructuredResponse:
        raise NotImplementedError

    def _check_command_exists(self) -> None:
        if Path(self.command).exists():
            return
        if shutil.which(self.command):
            return
        raise LlmPatchClientError(f"{self.provider_name} CLI not found: {self.command}")

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

    def _check_authentication(self) -> None:
        completed = self._run([self.command, "login", "status"], cwd=Path.cwd())
        if "Logged in" not in completed.stdout:
            detail = completed.stdout.strip() or completed.stderr.strip() or "Codex login status unavailable"
            raise LlmPatchClientError(f"Codex OAuth session not ready: {detail}")

    def generate_patch_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
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
            )


class ClaudeCodePatchCliClient(BasePatchCliClient):
    provider_name = "claude_code"

    def _check_authentication(self) -> None:
        completed = self._run([self.command, "auth", "status"], cwd=Path.cwd())
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise LlmPatchClientError("Claude auth status output was not valid JSON") from exc
        if not payload.get("loggedIn"):
            raise LlmPatchClientError("Claude Code OAuth session not ready. Run `claude auth login` first.")

    def generate_patch_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
    ) -> LlmStructuredResponse:
        self._ensure_ready()
        args = [
            self.command,
            "-p",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "",
            "--output-format",
            "text",
        ]
        if self.model:
            args.extend(["--model", self.model])
        args.append(prompt)
        completed = self._run(args, cwd=workdir)
        raw_text = completed.stdout
        return LlmStructuredResponse(
            payload=self._parse_json_payload(raw_text),
            raw_text=raw_text,
            provider=self.provider_name,
            model=self.model,
        )
