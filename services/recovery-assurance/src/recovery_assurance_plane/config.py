from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .constants import PHASE2_RETRY_CHANNEL, PHASE3_VALIDATE_CHANNEL, PHASE4_PROMOTE_CHANNEL


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    artifact_dir: Path
    redis_url: str | None
    validate_channel: str
    retry_channel: str
    promote_channel: str
    stable_image: str
    startup_timeout_seconds: int
    max_p95_latency_increase_pct: float
    max_error_rate_increase_pp: float
    max_throughput_drop_pct: float


def load_settings() -> Settings:
    data_dir = Path(os.getenv("RA_DATA_DIR", "data")).resolve()
    artifact_dir = Path(os.getenv("RA_ARTIFACT_DIR", "artifacts/recovery_assurance")).resolve()
    return Settings(
        data_dir=data_dir,
        artifact_dir=artifact_dir,
        redis_url=os.getenv("REDIS_URL"),
        validate_channel=os.getenv("RA_VALIDATE_CHANNEL", PHASE3_VALIDATE_CHANNEL),
        retry_channel=os.getenv("RA_RETRY_CHANNEL", PHASE2_RETRY_CHANNEL),
        promote_channel=os.getenv("RA_PROMOTE_CHANNEL", PHASE4_PROMOTE_CHANNEL),
        stable_image=os.getenv("RA_STABLE_IMAGE", "registry.local/target-app:stable"),
        startup_timeout_seconds=int(os.getenv("RA_STARTUP_TIMEOUT_SECONDS", "120")),
        max_p95_latency_increase_pct=float(os.getenv("RA_MAX_P95_LATENCY_INCREASE_PCT", "15")),
        max_error_rate_increase_pp=float(os.getenv("RA_MAX_ERROR_RATE_INCREASE_PP", "1")),
        max_throughput_drop_pct=float(os.getenv("RA_MAX_THROUGHPUT_DROP_PCT", "10")),
    )

