from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.secure_coding_plane.build import SecureCodingBuildEngine
from src.secure_coding_plane.config import PlaneSettings
from src.secure_coding_plane.storage import PlaneStore


class SecureCodingBuildEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.store = PlaneStore(root / "secure_coding.db")
        self.artifact_root = root / "artifacts"
        self.workspace_root = root / "workspace"
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def test_infers_candidate_image_from_docker_tag_flag(self) -> None:
        settings = PlaneSettings(
            workspace_root=self.workspace_root,
            artifact_root=self.artifact_root,
            db_path=Path(self.temp_dir.name) / "secure_coding.db",
            redis_url=None,
            secure_coding_build_mode="command",
            secure_coding_build_command="docker build -t ghcr.io/mjsec-mju/app:candidate-123 .",
        )
        engine = SecureCodingBuildEngine(settings, self.store, self.artifact_root)

        candidate_image = engine._resolve_candidate_image("evt-001", "patch-001")

        self.assertEqual("ghcr.io/mjsec-mju/app:candidate-123", candidate_image)

    def test_explicit_build_image_tag_overrides_command_inference(self) -> None:
        settings = PlaneSettings(
            workspace_root=self.workspace_root,
            artifact_root=self.artifact_root,
            db_path=Path(self.temp_dir.name) / "secure_coding.db",
            redis_url=None,
            secure_coding_build_mode="command",
            secure_coding_build_command="docker build -t ghcr.io/mjsec-mju/app:wrong-tag .",
            secure_coding_build_image_tag="ghcr.io/mjsec-mju/app:actual-tag",
        )
        engine = SecureCodingBuildEngine(settings, self.store, self.artifact_root)

        candidate_image = engine._resolve_candidate_image("evt-001", "patch-001")

        self.assertEqual("ghcr.io/mjsec-mju/app:actual-tag", candidate_image)

    def test_default_candidate_image_uses_ghcr_registry_prefix(self) -> None:
        settings = PlaneSettings(
            workspace_root=self.workspace_root,
            artifact_root=self.artifact_root,
            db_path=Path(self.temp_dir.name) / "secure_coding.db",
            redis_url=None,
        )
        engine = SecureCodingBuildEngine(settings, self.store, self.artifact_root)

        candidate_image = engine._resolve_candidate_image("evt-001", "patch-001")

        self.assertEqual(
            "ghcr.io/mjsec-mju/elden-target-app:candidate-evt-001-patch-001",
            candidate_image,
        )

    def test_rejects_candidate_images_outside_allowed_registry(self) -> None:
        settings = PlaneSettings(
            workspace_root=self.workspace_root,
            artifact_root=self.artifact_root,
            db_path=Path(self.temp_dir.name) / "secure_coding.db",
            redis_url=None,
            secure_coding_build_image_tag="repo/app:actual-tag",
        )
        engine = SecureCodingBuildEngine(settings, self.store, self.artifact_root)

        with self.assertRaisesRegex(ValueError, "ghcr.io/mjsec-mju"):
            engine._resolve_candidate_image("evt-001", "patch-001")


if __name__ == "__main__":
    unittest.main()
