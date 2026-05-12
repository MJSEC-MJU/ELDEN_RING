from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PlaneSettings:
    workspace_root: Path
    artifact_root: Path
    db_path: Path
    redis_url: str | None
    secure_coding_ingest_channel: str = "elden:phase2:context"
    secure_coding_validate_channel: str = "elden:phase3:validate"
    secure_coding_retry_channel: str = "elden:phase2:retry"
    secure_coding_llm_provider: str = "codex"
    secure_coding_codex_command: str = "codex"
    secure_coding_codex_model: str | None = None
    secure_coding_claude_command: str = "claude"
    secure_coding_claude_model: str | None = None
    secure_coding_anthropic_api_key: str | None = None
    secure_coding_anthropic_model: str = "claude-sonnet-4-6"
    secure_coding_llm_timeout_sec: int = 180
    secure_coding_llm_temperature: float = 0.2
    secure_coding_llm_max_tokens: int = 2048
    secure_coding_prompt_cache_enabled: bool = True
    secure_coding_max_patch_retry: int = 3
    secure_coding_retry_temp_step: float = 0.3
    secure_coding_retry_temp_cap: float = 1.0
    secure_coding_apply_mode: str = "workspace"
    secure_coding_apply_rollback_on_failure: bool = True
    secure_coding_build_mode: str = "simulate"
    secure_coding_build_command: str | None = None
    secure_coding_build_image_tag: str | None = None


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


def load_settings() -> PlaneSettings:
    cwd = Path.cwd()
    workspace_root = Path(os.getenv("PLANE_WORKSPACE_ROOT", str(cwd / "runtime" / "workspace"))).resolve()
    artifact_root = Path(os.getenv("PLANE_ARTIFACT_ROOT", str(cwd / "artifacts"))).resolve()
    db_path = Path(os.getenv("PLANE_DB_PATH", str(cwd / "secure_coding.db"))).resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    artifact_root.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return PlaneSettings(
        workspace_root=workspace_root,
        artifact_root=artifact_root,
        db_path=db_path,
        redis_url=os.getenv("PLANE_REDIS_URL"),
        secure_coding_ingest_channel=os.getenv("SECURE_CODING_INGEST_CHANNEL", "elden:phase2:context"),
        secure_coding_validate_channel=os.getenv("SECURE_CODING_VALIDATE_CHANNEL", "elden:phase3:validate"),
        secure_coding_retry_channel=os.getenv("SECURE_CODING_RETRY_CHANNEL", "elden:phase2:retry"),
        secure_coding_llm_provider=os.getenv("SECURE_CODING_LLM_PROVIDER", "codex"),
        secure_coding_codex_command=os.getenv("SECURE_CODING_CODEX_COMMAND", "codex"),
        secure_coding_codex_model=os.getenv("SECURE_CODING_CODEX_MODEL"),
        secure_coding_claude_command=os.getenv("SECURE_CODING_CLAUDE_COMMAND", "claude"),
        secure_coding_claude_model=os.getenv("SECURE_CODING_CLAUDE_MODEL"),
        secure_coding_anthropic_api_key=os.getenv("SECURE_CODING_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY"),
        secure_coding_anthropic_model=os.getenv("SECURE_CODING_ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        secure_coding_llm_timeout_sec=int(os.getenv("SECURE_CODING_LLM_TIMEOUT_SEC", "180")),
        secure_coding_llm_temperature=float(os.getenv("SECURE_CODING_LLM_TEMPERATURE", "0.2")),
        secure_coding_llm_max_tokens=int(os.getenv("SECURE_CODING_LLM_MAX_TOKENS", "2048")),
        secure_coding_prompt_cache_enabled=_bool("SECURE_CODING_PROMPT_CACHE_ENABLED", True),
        secure_coding_max_patch_retry=int(os.getenv("SECURE_CODING_MAX_PATCH_RETRY", "3")),
        secure_coding_retry_temp_step=float(os.getenv("SECURE_CODING_RETRY_TEMP_STEP", "0.3")),
        secure_coding_retry_temp_cap=float(os.getenv("SECURE_CODING_RETRY_TEMP_CAP", "1.0")),
        secure_coding_apply_mode=os.getenv("SECURE_CODING_APPLY_MODE", "workspace"),
        secure_coding_apply_rollback_on_failure=_bool("SECURE_CODING_APPLY_ROLLBACK_ON_FAILURE", True),
        secure_coding_build_mode=os.getenv("SECURE_CODING_BUILD_MODE", "simulate"),
        secure_coding_build_command=os.getenv("SECURE_CODING_BUILD_COMMAND"),
        secure_coding_build_image_tag=os.getenv("SECURE_CODING_BUILD_IMAGE_TAG"),
    )
