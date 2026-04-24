from __future__ import annotations

import re
import shlex
import subprocess
from typing import Any

from .config import PlaneSettings
from .schemas import BuildResponse, BuildResult, PatchStrategy
from .storage import PlaneStore
from .utils import generate_id, write_text


class SecureCodingBuildEngine:
    allowed_registry_prefix = "ghcr.io/mjsec-mju/"

    def __init__(self, settings: PlaneSettings, store: PlaneStore, artifact_root) -> None:
        self.settings = settings
        self.store = store
        self.artifact_root = artifact_root

    def run_build(self, job_id: str, context: dict[str, Any], patch_id: str, strategy: PatchStrategy) -> BuildResponse:
        self.store.update_secure_job(job_id, status="BUILDING_IMAGE", current_step="build", progress=90)
        build_id = generate_id("build")
        build_log_path = self.artifact_root / "builds" / f"{build_id}.log"
        candidate_image = self._resolve_candidate_image(context["event_id"], patch_id)
        if self.settings.secure_coding_build_mode == "command" and self.settings.secure_coding_build_command:
            completed = subprocess.run(
                self.settings.secure_coding_build_command,
                cwd=self.settings.workspace_root,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
            )
            log_text = "\n".join(
                [
                    "build_mode=command",
                    f"job_id={job_id}",
                    f"patch_id={patch_id}",
                    f"candidate_image={candidate_image}",
                    f"build_command={self.settings.secure_coding_build_command}",
                    "",
                    completed.stdout,
                    completed.stderr,
                ]
            )
            if completed.returncode != 0:
                raise RuntimeError(f"Build command failed: {completed.returncode}")
        else:
            log_text = "\n".join(
                [
                    "build_mode=simulate",
                    f"job_id={job_id}",
                    f"patch_id={patch_id}",
                    f"candidate_image={candidate_image}",
                    f"fix_goal={strategy.fix_goal}",
                ]
            )
        write_text(build_log_path, log_text)
        self.store.save_secure_build(
            build_id=build_id,
            job_id=job_id,
            patch_id=patch_id,
            candidate_image=candidate_image,
            build_log=str(build_log_path),
            build_status="success",
        )
        return BuildResponse(
            job_id=job_id,
            status="success",
            build_result=BuildResult(
                candidate_image=candidate_image,
                build_log=str(build_log_path),
                patch_status="READY_FOR_VALIDATION",
            ),
        )

    def _resolve_candidate_image(self, event_id: str, patch_id: str) -> str:
        if self.settings.secure_coding_build_image_tag:
            candidate_image = self.settings.secure_coding_build_image_tag
            self._validate_candidate_image(candidate_image)
            return candidate_image
        if self.settings.secure_coding_build_mode == "command" and self.settings.secure_coding_build_command:
            inferred_tag = self._infer_image_tag_from_build_command(self.settings.secure_coding_build_command)
            if inferred_tag:
                self._validate_candidate_image(inferred_tag)
                return inferred_tag
        candidate_image = (
            "ghcr.io/mjsec-mju/elden-target-app:"
            f"candidate-{self._normalize_tag_fragment(event_id)}-{self._normalize_tag_fragment(patch_id)}"
        )
        self._validate_candidate_image(candidate_image)
        return candidate_image

    def _infer_image_tag_from_build_command(self, command: str) -> str | None:
        for posix in (True, False):
            try:
                tokens = shlex.split(command, posix=posix)
            except ValueError:
                continue
            inferred = self._extract_tag_from_tokens(tokens)
            if inferred:
                return inferred
        return None

    def _extract_tag_from_tokens(self, tokens: list[str]) -> str | None:
        normalized = [token.strip("\"'") for token in tokens]
        if not normalized:
            return None
        joined = " ".join(normalized)
        if "docker" not in joined and "podman" not in joined:
            return None
        if "build" not in normalized:
            return None
        for index, token in enumerate(normalized):
            if token in {"-t", "--tag"} and index + 1 < len(normalized):
                return normalized[index + 1].strip("\"'")
            if token.startswith("--tag="):
                return token.split("=", 1)[1].strip("\"'")
        return None

    def _normalize_tag_fragment(self, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip(".-")
        return normalized or "unknown"

    def _validate_candidate_image(self, candidate_image: str) -> None:
        if not candidate_image.startswith(self.allowed_registry_prefix):
            raise ValueError(
                "Candidate image must use the ghcr.io/mjsec-mju/* registry prefix "
                f"for Kyverno policy compatibility: {candidate_image}"
            )
