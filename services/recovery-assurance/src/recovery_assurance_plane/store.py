from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from threading import Lock
from typing import Any


class JsonStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "phase3-store.json"
        self._lock = Lock()
        if not self.path.exists():
            self._write({"jobs": {}, "stages": {}, "runtime_contexts": {}, "messages": []})

    def create_job(self, job: dict[str, Any]) -> None:
        with self._lock:
            data = self._read()
            data["jobs"][job["validation_job_id"]] = job
            data["stages"].setdefault(job["validation_job_id"], {})
            self._write(data)

    def get_job(self, validation_job_id: str) -> dict[str, Any] | None:
        with self._lock:
            return deepcopy(self._read()["jobs"].get(validation_job_id))

    def get_job_by_patch(self, patch_id: str) -> dict[str, Any] | None:
        with self._lock:
            for job in self._read()["jobs"].values():
                if job["patch_id"] == patch_id and job["status"] not in {"FAILED", "CANCELED"}:
                    return deepcopy(job)
        return None

    def update_job(self, validation_job_id: str, **updates: Any) -> None:
        with self._lock:
            data = self._read()
            if validation_job_id not in data["jobs"]:
                raise KeyError(validation_job_id)
            data["jobs"][validation_job_id].update(updates)
            self._write(data)

    def save_stage(self, validation_job_id: str, stage_name: str, result: dict[str, Any]) -> None:
        with self._lock:
            data = self._read()
            data["stages"].setdefault(validation_job_id, {})[stage_name] = result
            self._write(data)

    def get_stages(self, validation_job_id: str) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._read()["stages"].get(validation_job_id, {}))

    def save_runtime_context(self, context_id: str, runtime_context: dict[str, Any]) -> None:
        with self._lock:
            data = self._read()
            data["runtime_contexts"][context_id] = runtime_context
            self._write(data)

    def get_runtime_context(self, context_id: str) -> dict[str, Any] | None:
        with self._lock:
            return deepcopy(self._read()["runtime_contexts"].get(context_id))

    def save_message(self, channel: str, payload: dict[str, Any]) -> None:
        with self._lock:
            data = self._read()
            data["messages"].append({"channel": channel, "payload": payload})
            self._write(data)

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

