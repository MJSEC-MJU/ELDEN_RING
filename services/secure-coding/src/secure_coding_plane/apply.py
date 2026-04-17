from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException

from .config import PlaneSettings
from .schemas import ApplyResponse, ApplyResult
from .storage import PlaneStore
from .utils import resolve_workspace_path, write_text


class SecureCodingApplyEngine:
    def __init__(self, settings: PlaneSettings, store: PlaneStore, artifact_root) -> None:
        self.settings = settings
        self.store = store
        self.artifact_root = artifact_root

    def run_apply(self, job_id: str, patch_id: str) -> ApplyResponse:
        mode = self.settings.secure_coding_apply_mode.lower()
        patch_row = self.store.get_secure_patch(patch_id)
        if not patch_row:
            raise HTTPException(status_code=404, detail="Patch not found")

        if mode == "artifact_only":
            return ApplyResponse(
                job_id=job_id,
                status="success",
                apply_result=ApplyResult(applied=False, mode=mode, patch_status=patch_row["patch_status"]),
            )

        if mode != "workspace":
            raise RuntimeError(f"Unsupported apply mode: {self.settings.secure_coding_apply_mode}")

        self.store.update_secure_job(job_id, status="APPLYING_PATCH", current_step="apply", progress=85)
        if patch_row["patch_status"] != "READY_FOR_BUILD":
            raise RuntimeError("Patch must pass recheck before apply")
        if not patch_row.get("patched_file_path"):
            raise RuntimeError("Patched file artifact is missing")

        workspace_file = resolve_workspace_path(self.settings.workspace_root, patch_row["target_file"])
        if not workspace_file.exists():
            raise RuntimeError(f"Workspace target file does not exist: {patch_row['target_file']}")

        original_snapshot = self.artifact_root / "original_src" / job_id / patch_row["target_file"]
        if not original_snapshot.exists():
            raise RuntimeError("Original source snapshot is missing")

        current_content = workspace_file.read_text(encoding="utf-8")
        original_content = original_snapshot.read_text(encoding="utf-8")
        if current_content != original_content:
            raise RuntimeError(f"Workspace drift detected before apply: {patch_row['target_file']}")

        patched_content = Path(patch_row["patched_file_path"]).read_text(encoding="utf-8")
        backup_file = self.artifact_root / "workspace_backup" / job_id / patch_row["target_file"]
        write_text(backup_file, current_content)
        write_text(workspace_file, patched_content)

        change_summary = dict(patch_row["change_summary_json"])
        change_summary.update(
            {
                "workspace_applied": True,
                "workspace_file": str(workspace_file),
                "backup_file": str(backup_file),
                "apply_mode": mode,
            }
        )
        self.store.save_secure_patch(
            patch_id=patch_row["patch_id"],
            job_id=patch_row["job_id"],
            event_id=patch_row["event_id"],
            target_file=patch_row["target_file"],
            target_function=patch_row["target_function"],
            patch_file=patch_row["patch_file"],
            unified_diff=patch_row["unified_diff"],
            patch_status=patch_row["patch_status"],
            change_summary=change_summary,
            patched_file_path=patch_row.get("patched_file_path"),
        )
        return ApplyResponse(
            job_id=job_id,
            status="success",
            apply_result=ApplyResult(
                applied=True,
                mode=mode,
                workspace_file=str(workspace_file),
                backup_file=str(backup_file),
                patch_status=patch_row["patch_status"],
            ),
        )

    def rollback_apply(self, job_id: str, patch_id: str) -> bool:
        patch_row = self.store.get_secure_patch(patch_id)
        if not patch_row:
            return False
        change_summary = patch_row["change_summary_json"]
        workspace_file = change_summary.get("workspace_file")
        backup_file = change_summary.get("backup_file")
        if not workspace_file or not backup_file:
            return False
        backup_path = Path(backup_file)
        workspace_path = Path(workspace_file)
        if not backup_path.exists():
            return False
        write_text(workspace_path, backup_path.read_text(encoding="utf-8"))
        change_summary["workspace_applied"] = False
        change_summary["rolled_back"] = True
        self.store.save_secure_patch(
            patch_id=patch_row["patch_id"],
            job_id=patch_row["job_id"],
            event_id=patch_row["event_id"],
            target_file=patch_row["target_file"],
            target_function=patch_row["target_function"],
            patch_file=patch_row["patch_file"],
            unified_diff=patch_row["unified_diff"],
            patch_status=patch_row["patch_status"],
            change_summary=change_summary,
            patched_file_path=patch_row.get("patched_file_path"),
        )
        return True
