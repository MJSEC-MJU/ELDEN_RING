from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def generate_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    ensure_parent(path)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def dump_model(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    if hasattr(model, "dict"):
        return model.dict()
    raise TypeError(f"Unsupported model type: {type(model)!r}")


def resolve_workspace_path(workspace_root: Path, relative_path: str) -> Path:
    candidate = (workspace_root / relative_path).resolve()
    workspace_root = workspace_root.resolve()
    try:
        candidate.relative_to(workspace_root)
    except ValueError as exc:
        raise ValueError(f"Target path escapes workspace root: {relative_path}") from exc
    return candidate


def extract_code_window(content: str, line_start: int, line_end: int, padding: int = 2) -> tuple[str, int, int]:
    lines = content.splitlines()
    start_idx = max(line_start - 1 - padding, 0)
    end_idx = min(line_end + padding, len(lines))
    return "\n".join(lines[start_idx:end_idx]), start_idx + 1, end_idx


def file_exists(path: Path) -> bool:
    return path.exists() and path.is_file()


def safe_relpath(path: Path, start: Path) -> str:
    try:
        return os.path.relpath(path, start)
    except ValueError:
        return str(path)
