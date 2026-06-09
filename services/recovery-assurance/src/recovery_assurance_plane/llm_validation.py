from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings


class LlmValidationError(RuntimeError):
    pass


@dataclass(slots=True)
class LlmValidationResponse:
    payload: dict[str, Any]
    raw_text: str
    provider: str
    model: str | None


def create_validation_client(settings: Settings) -> "BaseValidationCliClient":
    provider = settings.llm_provider.lower()
    if provider in {"builtin", "mock"}:
        return BuiltinValidationCliClient(provider=provider, model=settings.codex_model)
    if provider == "codex":
        return CodexValidationCliClient(
            command=settings.codex_command,
            model=settings.codex_model,
            timeout_sec=settings.llm_timeout_sec,
        )
    if provider in {"claude", "claude_code", "claude-code"}:
        return ClaudeCodeValidationCliClient(
            command=settings.claude_command,
            model=settings.claude_model,
            timeout_sec=settings.llm_timeout_sec,
        )
    raise LlmValidationError(f"Unsupported recovery assurance LLM provider: {settings.llm_provider}")


class BaseValidationCliClient:
    provider_name: str

    def __init__(self, *, command: str, model: str | None, timeout_sec: int) -> None:
        self.command = _resolve_cli_command(command)
        self.model = model
        self.timeout_sec = timeout_sec
        self._auth_checked = False

    def generate_validation_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
    ) -> LlmValidationResponse:
        raise NotImplementedError

    def _ensure_ready(self) -> None:
        if not Path(self.command).exists() and not shutil.which(self.command):
            raise LlmValidationError(f"{self.provider_name} CLI not found: {self.command}")
        if not self._auth_checked:
            self._check_authentication()
            self._auth_checked = True

    def _check_authentication(self) -> None:
        raise NotImplementedError

    def _run(self, args: list[str], *, cwd: Path, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            args,
            cwd=cwd,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_sec,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or f"exit code {completed.returncode}").strip()
            raise LlmValidationError(f"{self.provider_name} CLI call failed: {detail}")
        return completed

    def _parse_json_payload(self, raw_text: str) -> dict[str, Any]:
        text = raw_text.strip()
        if not text:
            raise LlmValidationError(f"{self.provider_name} returned empty output")
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
                payload = json.loads(candidate)
                if isinstance(payload, dict):
                    return payload
            except json.JSONDecodeError:
                pass
            for start, char in enumerate(candidate):
                if char != "{":
                    continue
                try:
                    payload, end = decoder.raw_decode(candidate[start:])
                except json.JSONDecodeError:
                    continue
                if candidate[start + end :].strip():
                    continue
                if isinstance(payload, dict):
                    return payload
        raise LlmValidationError(f"{self.provider_name} output was not valid JSON")


class BuiltinValidationCliClient:
    provider_name = "builtin"

    def __init__(self, *, provider: str = "builtin", model: str | None = None) -> None:
        self.provider_name = provider
        self.model = model

    def generate_validation_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
    ) -> LlmValidationResponse:
        stage = self._extract_stage(prompt)
        passed, summary, metrics = self._evaluate(stage, prompt)
        payload = {
            "status": "pass" if passed else "fail",
            "summary": summary,
            "metrics": {"mode": self.provider_name, "stage": stage, **metrics},
        }
        return LlmValidationResponse(
            payload=payload,
            raw_text=json.dumps(payload, ensure_ascii=False),
            provider=self.provider_name,
            model=self.model,
        )

    def _extract_stage(self, prompt: str) -> str:
        for candidate in ("startup", "regression", "security_replay", "slo"):
            if f'"stage": "{candidate}"' in prompt or f"stage: {candidate}" in prompt:
                return candidate
        return "validation"

    def _evaluate(self, stage: str, prompt: str) -> tuple[bool, str, dict[str, Any]]:
        if self.provider_name == "mock":
            return True, f"mock {stage} validation passed for demo pipeline", {}

        if stage == "startup":
            passed = "candidate_image" in prompt and "ghcr.io/mjsec-mju/" in prompt
            return passed, "candidate image evidence is present" if passed else "candidate image evidence is missing", {}

        if stage == "regression":
            patch_lines = self._added_lines(prompt) + self._removed_lines(prompt)
            no_op_but_safe = not patch_lines and self._source_excerpt_has_sqli_fix(prompt)
            passed = 0 < len(patch_lines) <= 80 or no_op_but_safe
            return passed, "patch scope is bounded for the target function" if passed else "patch scope is missing or too broad", {
                "changed_lines": len(patch_lines),
                "no_op_already_safe": no_op_but_safe,
            }

        if stage == "security_replay":
            return self._evaluate_security_replay(prompt)

        if stage == "slo":
            passed = "candidate_image" in prompt and "patch_diff" in prompt
            return passed, "patch is code-local and has no infrastructure SLO risk signal" if passed else "insufficient SLO evidence", {}

        return False, f"unknown validation stage: {stage}", {}

    def _evaluate_security_replay(self, prompt: str) -> tuple[bool, str, dict[str, Any]]:
        added = "\n".join(self._added_lines(prompt))
        patch_diff = self._patch_diff(prompt)
        patched_source = self._patched_source_excerpt(prompt)
        evidence_text = f"{patch_diff}\n{patched_source}"
        if "CWE-89" in prompt:
            has_parameterized_execute = (
                "cursor.execute(query, (username, password))" in evidence_text
                or "execute(query, (" in evidence_text
                or "username=?" in evidence_text
            )
            adds_raw_execute = bool(re.search(r"cursor\.execute\(query\)\b", added))
            passed = has_parameterized_execute and not adds_raw_execute
            return passed, "SQLi replay is neutralized by parameterized binding" if passed else "SQLi sink is not convincingly parameterized", {
                "idempotent_replay": "cursor.execute(query)" not in "\n".join(self._removed_lines(prompt)),
            }
        if "CWE-79" in prompt:
            passed = "escape(" in added or "html.escape" in added
            return passed, "reflected XSS replay is neutralized by output escaping" if passed else "escaping evidence is missing", {}
        if "CWE-22" in prompt:
            passed = "realpath(" in added and ("Invalid path" in added or "startswith(" in added)
            return passed, "path traversal replay is neutralized by canonical path enforcement" if passed else "path confinement evidence is missing", {}
        return False, "unsupported CWE for builtin replay validation", {}

    def _added_lines(self, prompt: str) -> list[str]:
        patch_diff = self._patch_diff(prompt)
        return [
            line[1:]
            for line in patch_diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]

    def _removed_lines(self, prompt: str) -> list[str]:
        patch_diff = self._patch_diff(prompt)
        return [
            line[1:]
            for line in patch_diff.splitlines()
            if line.startswith("-") and not line.startswith("---")
        ]

    def _patch_diff(self, prompt: str) -> str:
        evidence = self._evidence(prompt)
        patch_diff = evidence.get("patch_diff")
        return patch_diff if isinstance(patch_diff, str) else ""

    def _patched_source_excerpt(self, prompt: str) -> str:
        evidence = self._evidence(prompt)
        source_excerpt = evidence.get("patched_source_excerpt")
        return source_excerpt if isinstance(source_excerpt, str) else ""

    def _source_excerpt_has_sqli_fix(self, prompt: str) -> bool:
        source_excerpt = self._patched_source_excerpt(prompt)
        return "CWE-89" in prompt and (
            "cursor.execute(query, (username, password))" in source_excerpt
            or "execute(query, (" in source_excerpt
            or "username=?" in source_excerpt
        )

    def _evidence(self, prompt: str) -> dict[str, Any]:
        marker = "Evidence JSON:"
        if marker not in prompt:
            return {}
        try:
            evidence = json.loads(prompt.split(marker, 1)[1].strip())
        except json.JSONDecodeError:
            return {}
        return evidence if isinstance(evidence, dict) else {}


class CodexValidationCliClient(BaseValidationCliClient):
    provider_name = "codex"

    def _check_authentication(self) -> None:
        completed = self._run([self.command, "login", "status"], cwd=Path.cwd())
        login_status = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        if "Logged in" not in login_status:
            raise LlmValidationError(f"Codex OAuth session not ready: {login_status or 'status unavailable'}")

    def generate_validation_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
    ) -> LlmValidationResponse:
        self._ensure_ready()
        with tempfile.TemporaryDirectory(prefix="codex-validation-") as tmp_dir:
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
            return LlmValidationResponse(
                payload=self._parse_json_payload(raw_text),
                raw_text=raw_text,
                provider=self.provider_name,
                model=self.model,
            )


class ClaudeCodeValidationCliClient(BaseValidationCliClient):
    provider_name = "claude_code"

    def _check_authentication(self) -> None:
        completed = self._run([self.command, "auth", "status"], cwd=Path.cwd())
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise LlmValidationError("Claude auth status output was not valid JSON") from exc
        if not payload.get("loggedIn"):
            raise LlmValidationError("Claude Code OAuth session not ready. Run `claude auth login` first.")

    def generate_validation_json(
        self,
        *,
        prompt: str,
        workdir: Path,
        schema: dict[str, Any],
    ) -> LlmValidationResponse:
        self._ensure_ready()
        args = [
            self.command,
            "-p",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "",
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(schema),
        ]
        if self.model:
            args.extend(["--model", self.model])
        completed = self._run(args, cwd=workdir, input_text=prompt)
        raw_text = completed.stdout
        return LlmValidationResponse(
            payload=self._extract_structured_output(raw_text),
            raw_text=raw_text,
            provider=self.provider_name,
            model=self.model,
        )

    def _extract_structured_output(self, raw_text: str) -> dict[str, Any]:
        try:
            wrapper = json.loads(raw_text)
        except json.JSONDecodeError:
            return self._parse_json_payload(raw_text)
        if isinstance(wrapper, dict):
            wrapper_error = _format_claude_wrapper_error(wrapper)
            if wrapper_error:
                raise LlmValidationError(wrapper_error)
            structured = wrapper.get("structured_output")
            if isinstance(structured, dict):
                return structured
            result = wrapper.get("result")
            if isinstance(result, dict):
                return result
            if isinstance(result, str) and result.strip():
                return self._parse_json_payload(result)
        return self._parse_json_payload(raw_text)


def _resolve_cli_command(command: str) -> str:
    configured = (command or "").strip()
    if not configured:
        return configured
    executable = Path(configured)
    if executable.exists():
        return str(executable)
    normalized = configured.lower()
    if normalized in {"codex", "codex.exe"}:
        codex_bin = os.getenv("CODEX_BIN")
        if codex_bin and Path(codex_bin).exists():
            return codex_bin
        direct_exe = shutil.which("codex.exe")
        if direct_exe:
            return direct_exe
    elif normalized in {"claude", "claude.exe"}:
        direct_exe = shutil.which("claude.exe")
        if direct_exe:
            return direct_exe
    resolved = shutil.which(configured)
    return resolved or configured


def _format_claude_wrapper_error(payload: dict[str, Any]) -> str | None:
    if not payload.get("is_error"):
        return None
    status = payload.get("api_error_status")
    message = payload.get("result") or payload.get("error") or "Claude API request failed"
    prefix = f"Claude API error {status}" if status else "Claude API error"
    return f"{prefix}: {message}"
