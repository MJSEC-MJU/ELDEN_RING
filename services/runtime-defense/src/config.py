"""Environment-based configuration for runtime-defense-controller."""

import os


def _int_env(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


class Settings:
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = _int_env("PORT", 8080)

    REDIS_HOST: str = os.environ.get("REDIS_HOST", "redis-master.elden-monitoring")
    REDIS_PORT: int = _int_env("REDIS_PORT", 6379)
    REDIS_PUBSUB_CHANNEL: str = os.environ.get(
        "REDIS_PUBSUB_CHANNEL", "elden:phase2:context"
    )
    REDIS_QUEUE_KEY: str = os.environ.get(
        "REDIS_QUEUE_KEY", "elden:phase2:context:queue"
    )
    REDIS_CONNECT_TIMEOUT: float = float(os.environ.get("REDIS_CONNECT_TIMEOUT", "2.0"))
    REDIS_OP_TIMEOUT: float = float(os.environ.get("REDIS_OP_TIMEOUT", "2.0"))

    ROUTE_MAP_PATH: str = os.environ.get("ROUTE_MAP_PATH", "/config/routes.json")

    K8S_NAMESPACE: str = os.environ.get("K8S_NAMESPACE", "elden-production")

    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

    # Webhook auth (Bearer token). Empty value disables enforcement (dev-only).
    WEBHOOK_AUTH_TOKEN: str = os.environ.get("WEBHOOK_AUTH_TOKEN", "")

    # Defense thresholds
    IP_BLOCK_THRESHOLD: int = _int_env("IP_BLOCK_THRESHOLD", 3)
    ENDPOINT_DISABLE_THRESHOLD: int = _int_env("ENDPOINT_DISABLE_THRESHOLD", 5)
    RATE_LIMIT_RPM: int = _int_env("RATE_LIMIT_RPM", 10)

    # Reliability tunables
    MEMORY_BACKUP_MAX_SIZE: int = _int_env("MEMORY_BACKUP_MAX_SIZE", 1000)
    DRAIN_INTERVAL_SECONDS: int = _int_env("DRAIN_INTERVAL_SECONDS", 30)

    # Adapter payload cap (bytes). Limits Redis/Phase 2 payload size.
    MAX_PAYLOAD_BYTES: int = _int_env("MAX_PAYLOAD_BYTES", 1024)


settings = Settings()
