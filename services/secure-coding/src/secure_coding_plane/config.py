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
    secure_coding_ingest_queue: str = "elden:phase2:context:queue"
    secure_coding_validate_channel: str = "elden:phase3:validate"
    secure_coding_retry_channel: str = "elden:phase2:retry"
    secure_coding_llm_provider: str = "codex"
    secure_coding_codex_command: str = "codex"
    secure_coding_codex_model: str | None = None
    secure_coding_claude_command: str = "claude"
    secure_coding_claude_model: str | None = None
    secure_coding_llm_timeout_sec: int = 180
    secure_coding_max_retries: int = 3
    secure_coding_apply_mode: str = "workspace"
    secure_coding_apply_rollback_on_failure: bool = True
    secure_coding_build_mode: str = "simulate"
    secure_coding_build_command: str | None = None
    secure_coding_build_image_tag: str | None = None


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
        secure_coding_ingest_queue=os.getenv("SECURE_CODING_INGEST_QUEUE", "elden:phase2:context:queue"),
        secure_coding_validate_channel=os.getenv("SECURE_CODING_VALIDATE_CHANNEL", "elden:phase3:validate"),
        secure_coding_retry_channel=os.getenv("SECURE_CODING_RETRY_CHANNEL", "elden:phase2:retry"),
        secure_coding_llm_provider=os.getenv("SECURE_CODING_LLM_PROVIDER", "codex"),
        secure_coding_codex_command=os.getenv("SECURE_CODING_CODEX_COMMAND", "codex"),
        secure_coding_codex_model=os.getenv("SECURE_CODING_CODEX_MODEL"),
        secure_coding_claude_command=os.getenv("SECURE_CODING_CLAUDE_COMMAND", "claude"),
        secure_coding_claude_model=os.getenv("SECURE_CODING_CLAUDE_MODEL"),
        secure_coding_llm_timeout_sec=int(os.getenv("SECURE_CODING_LLM_TIMEOUT_SEC", "180")),
        secure_coding_max_retries=int(os.getenv("SECURE_CODING_MAX_RETRIES", "3")),
        secure_coding_apply_mode=os.getenv("SECURE_CODING_APPLY_MODE", "workspace"),
        secure_coding_apply_rollback_on_failure=os.getenv("SECURE_CODING_APPLY_ROLLBACK_ON_FAILURE", "true").lower() in {"1", "true", "yes", "on"},
        secure_coding_build_mode=os.getenv("SECURE_CODING_BUILD_MODE", "simulate"),
        secure_coding_build_command=os.getenv("SECURE_CODING_BUILD_COMMAND"),
        secure_coding_build_image_tag=os.getenv("SECURE_CODING_BUILD_IMAGE_TAG"),
    )
